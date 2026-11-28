// Bounded H.264 RTP access-unit assembly for the observed Zalo and RFC 6184 formats.

use anyhow::{bail, ensure, Result};

const MAX_ACCESS_UNIT: usize = 1024 * 1024;

#[derive(Default, PartialEq, Eq)]
enum Fragment {
    #[default]
    None,
    Zalo,
    FuA(u8),
}

/// Stateful RTP video ingress, owned by one receiving worker.
#[derive(Default)]
pub struct VideoIngress {
    sequence: Option<u16>,
    timestamp: Option<u32>,
    unit: Vec<u8>,
    fragment: Fragment,
}

impl VideoIngress {
    /// Creates an empty assembler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Discards all partial access units and sequence state.
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Returns one complete Annex-B access unit at a marker or Zalo end fragment.
    ///
    /// # Errors
    /// Returns an error on loss, malformed packetization, or a unit larger than 1 MiB.
    pub fn push(
        &mut self,
        sequence: u16,
        timestamp: u32,
        marker: bool,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        let previous = self.sequence.replace(sequence);
        let result = (|| {
            ensure!(
                previous.is_none_or(|prev| prev.wrapping_add(1) == sequence),
                "video RTP sequence gap"
            );
            ensure!(
                self.timestamp.is_none_or(|ts| ts == timestamp),
                "video RTP timestamp changed before access unit ended"
            );
            ensure!(
                !payload.is_empty() && payload.len() <= MAX_ACCESS_UNIT,
                "invalid video payload size"
            );
            self.timestamp = Some(timestamp);
            if payload.starts_with(&[0, 0, 1]) || payload.starts_with(&[0, 0, 0, 1]) {
                ensure!(
                    self.fragment == Fragment::None,
                    "whole unit interrupted video fragment"
                );
                self.append(payload)?;
                return Ok(self.finish());
            }
            // The captured Zalo header uses FU type zero, which RFC 6184 forbids.
            // See re-notes/08 for the 1c 80 / 1c 00 / 1c 40 framing evidence.
            let zalo = payload.len() >= 2 && payload[0] == 0x1c && payload[1] & 0x3f == 0;
            if zalo {
                let flags = payload[1];
                if flags & 0x80 != 0 {
                    ensure!(
                        self.fragment == Fragment::None && self.unit.is_empty(),
                        "overlapping Zalo video fragments"
                    );
                    self.fragment = Fragment::Zalo;
                }
                ensure!(
                    self.fragment == Fragment::Zalo,
                    "missing Zalo fragment start"
                );
                ensure!(payload.len() > 2, "empty Zalo fragment");
                self.append(&payload[2..])?;
                if flags & 0x40 != 0 {
                    self.fragment = Fragment::None;
                    ensure!(
                        self.unit.starts_with(&[0, 0, 1]) || self.unit.starts_with(&[0, 0, 0, 1]),
                        "Zalo unit is not Annex-B"
                    );
                    return Ok(self.finish());
                }
            } else {
                ensure!(payload[0] & 0x80 == 0, "forbidden H264 NAL bit");
                match payload[0] & 0x1f {
                    1..=23 => {
                        ensure!(
                            self.fragment == Fragment::None,
                            "NAL interrupted video fragment"
                        );
                        self.append(&[0, 0, 0, 1])?;
                        self.append(payload)?;
                    }
                    24 => {
                        ensure!(
                            self.fragment == Fragment::None,
                            "STAP interrupted video fragment"
                        );
                        let mut offset = 1;
                        ensure!(offset < payload.len(), "empty STAP-A");
                        while offset < payload.len() {
                            ensure!(offset + 2 <= payload.len(), "truncated STAP-A length");
                            let len =
                                u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
                            offset += 2;
                            ensure!(
                                len > 0 && len <= payload.len() - offset,
                                "invalid STAP-A NAL length"
                            );
                            let nal = &payload[offset..offset + len];
                            ensure!(
                                nal[0] & 0x80 == 0 && (1..=23).contains(&(nal[0] & 0x1f)),
                                "invalid STAP-A NAL"
                            );
                            self.append(&[0, 0, 0, 1])?;
                            self.append(nal)?;
                            offset += len;
                        }
                    }
                    28 => {
                        ensure!(payload.len() > 2, "truncated FU-A");
                        let flags = payload[1];
                        let kind = flags & 0x1f;
                        ensure!(
                            (1..=23).contains(&kind) && flags & 0x20 == 0 && flags & 0xc0 != 0xc0,
                            "invalid FU-A flags"
                        );
                        let header = (payload[0] & 0xe0) | kind;
                        if flags & 0x80 != 0 {
                            ensure!(
                                self.fragment == Fragment::None,
                                "overlapping FU-A fragments"
                            );
                            self.fragment = Fragment::FuA(header);
                            self.append(&[0, 0, 0, 1, header])?;
                        }
                        ensure!(
                            self.fragment == Fragment::FuA(header),
                            "missing or inconsistent FU-A start"
                        );
                        self.append(&payload[2..])?;
                        if flags & 0x40 != 0 {
                            self.fragment = Fragment::None;
                        }
                    }
                    _ => bail!("unsupported H264 packetization"),
                }
            }
            if marker {
                ensure!(
                    self.fragment == Fragment::None,
                    "marker before video fragment end"
                );
                Ok(self.finish())
            } else {
                Ok(None)
            }
        })();
        if result.is_err() {
            self.unit.clear();
            self.timestamp = None;
            self.fragment = Fragment::None;
        }
        result
    }

    /// Append bytes while capping both the assembled access unit and the
    /// buffer capacity requested from the allocator.
    ///
    /// # Errors
    /// Returns an error if the bytes would grow the access unit beyond 1 MiB.
    fn append(&mut self, bytes: &[u8]) -> Result<()> {
        ensure!(
            bytes.len() <= MAX_ACCESS_UNIT - self.unit.len(),
            "video access unit exceeds 1 MiB"
        );
        // Vec's geometric growth can otherwise allocate almost twice the AU limit.
        if self.unit.capacity() - self.unit.len() < bytes.len() {
            let capacity = (self.unit.capacity() * 2)
                .max(self.unit.len() + bytes.len())
                .min(MAX_ACCESS_UNIT);
            self.unit.reserve_exact(capacity - self.unit.len());
        }
        self.unit.extend_from_slice(bytes);
        Ok(())
    }

    fn finish(&mut self) -> Option<Vec<u8>> {
        self.timestamp = None;
        self.fragment = Fragment::None;
        Some(std::mem::take(&mut self.unit))
    }
}
