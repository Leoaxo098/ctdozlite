#![allow(dead_code)]
include!("../src/lib.rs");

mod tests {
    use super::*;

    #[test]
    fn slice_header_unescape_ignores_coded_data_and_accepts_terminal_prevention() {
        assert_eq!(unescape(&[0, 0, 3]).unwrap(), vec![0, 0]);
        assert!(unescape(&[0, 0, 3, 4]).is_err());
        let mut nal = vec![1; 1024 * 1024];
        nal.extend_from_slice(&[0, 0, 3, 4]);
        assert_eq!(unescape_prefix(&nal, 64).unwrap(), vec![1; 64]);
    }

    fn red_rgb(width: usize, height: usize) -> Vec<u8> {
        [240, 20, 20].repeat(width * height)
    }

    /// Round-trip a red and black fixture through OpenH264 and check decoded
    /// dimensions, pixel layout, and representative colors.
    #[test]
    fn native_roundtrip_preserves_dimensions_color_and_black_content() {
        let mut rgb = red_rgb(320, 240);
        for y in 0..240 {
            for x in 0..80 {
                rgb[(y * 320 + x) * 3..(y * 320 + x) * 3 + 3].fill(0);
            }
        }
        let encoded = VideoEncoder::new()
            .unwrap()
            .encode_rgb(&rgb, 320, 240, true)
            .unwrap();
        let frame = VideoDecoder::new()
            .unwrap()
            .decode(&encoded)
            .unwrap()
            .expect("actual native frame");
        assert_eq!(
            (frame.width, frame.height, frame.rgba.len()),
            (320, 240, 320 * 240 * 4)
        );
        let red = &frame.rgba[(120 * 320 + 160) * 4..][..4];
        assert!(
            red[0] > 190 && red[1] < 55 && red[2] < 55 && red[3] == 255,
            "{red:?}"
        );
        assert!(frame.rgba[(120 * 320 + 20) * 4] < 20);
    }

    #[test]
    fn scales_non_four_three_input_with_black_padding() {
        let encoded = VideoEncoder::new()
            .unwrap()
            .encode_rgb(&red_rgb(640, 360), 640, 360, true)
            .unwrap();
        let frame = VideoDecoder::new()
            .unwrap()
            .decode(&encoded)
            .unwrap()
            .unwrap();
        assert!(frame.rgba[(10 * 320 + 160) * 4] < 20);
        assert!(frame.rgba[(120 * 320 + 160) * 4] > 190);
        assert!(frame.rgba[(230 * 320 + 160) * 4] < 20);
    }

    #[test]
    fn forced_idr_contains_fresh_parameter_sets_and_decodes_independently() {
        let mut encoder = VideoEncoder::new().unwrap();
        encoder
            .encode_rgb(&red_rgb(320, 240), 320, 240, false)
            .unwrap();
        encoder
            .encode_rgb(&red_rgb(320, 240), 320, 240, false)
            .unwrap();
        let forced = encoder
            .encode_rgb(&[20, 220, 20].repeat(320 * 240), 320, 240, true)
            .unwrap();
        let frame = VideoDecoder::new()
            .unwrap()
            .decode(&forced)
            .unwrap()
            .unwrap();
        assert!(frame.rgba[(120 * 320 + 160) * 4 + 1] > 170);
    }

    #[test]
    fn rejects_invalid_rgb_and_compressed_input() {
        let mut encoder = VideoEncoder::new().unwrap();
        assert!(encoder.encode_rgb(&[], 0, 240, false).is_err());
        assert!(encoder.encode_rgb(&[0; 3], 320, 240, false).is_err());
        let mut decoder = VideoDecoder::new().unwrap();
        assert!(decoder.decode(&vec![0; 1024 * 1024 + 1]).is_err());
        assert!(decoder.decode(&[0, 0, 1, 0x67, 0xff]).is_err());
        assert!(decoder.decode(&[0, 0, 1, 0x65, 0xff]).unwrap().is_none());
    }

    /// Check that separately received parameter sets enable IDR decoding
    /// until a reset clears them.
    #[test]
    fn accepts_parameter_sets_delivered_separately_before_idr() {
        let encoded = VideoEncoder::new()
            .unwrap()
            .encode_rgb(&red_rgb(320, 240), 320, 240, true)
            .unwrap();
        let nals = annexb_nals(&encoded).unwrap();
        let mut decoder = VideoDecoder::new().unwrap();
        let mut slices = Vec::new();
        for nal in nals {
            let mut unit = vec![0, 0, 0, 1];
            unit.extend_from_slice(nal);
            if matches!(nal[0] & 0x1f, 7 | 8) {
                assert!(decoder.decode(&unit).unwrap().is_none());
            } else {
                slices.extend(unit);
            }
        }
        assert!(decoder.decode(&slices).unwrap().is_some());
        decoder.reset().unwrap();
        assert!(decoder.decode(&slices).unwrap().is_none());
    }

    /// A synchronized decoder must accept a new PPS delivered before its first P slice.
    #[test]
    fn delivers_separate_pps_before_its_dependent_p_slice() {
        /// Replace ue(0) with ue(1) and preserve the rest of the CAVLC RBSP.
        fn with_pps_one(nal: &[u8], skip_fields: usize) -> Vec<u8> {
            let rbsp = unescape(&nal[1..]).unwrap();
            let start = {
                let mut bits = Bits::new(&rbsp);
                for _ in 0..skip_fields {
                    bits.ue().unwrap();
                }
                bits
            };
            let bit = start.offset;
            let mut bits = start;
            assert_eq!(bits.ue().unwrap(), 0);
            let mut rbsp_bits: Vec<_> = rbsp
                .iter()
                .flat_map(|byte| (0..8).rev().map(move |shift| (byte >> shift) & 1))
                .collect();
            rbsp_bits.splice(bit..bit + 1, [0, 1, 0]);
            rbsp_bits.resize(rbsp_bits.len().next_multiple_of(8), 0);
            let mut result = vec![0, 0, 0, 1, nal[0]];
            let mut zeros = 0;
            for chunk in rbsp_bits.chunks_exact(8) {
                let byte = chunk.iter().fold(0u8, |byte, bit| (byte << 1) | bit);
                if zeros == 2 && byte <= 3 {
                    result.push(3);
                    zeros = 0;
                }
                result.push(byte);
                zeros = if byte == 0 { zeros + 1 } else { 0 };
            }
            result
        }

        let mut encoder = VideoEncoder::new().unwrap();
        let idr = encoder
            .encode_rgb(&red_rgb(320, 240), 320, 240, true)
            .unwrap();
        let p = encoder
            .encode_rgb(&red_rgb(320, 240), 320, 240, false)
            .unwrap();
        let pps = annexb_nals(&idr)
            .unwrap()
            .into_iter()
            .find(|nal| nal[0] & 0x1f == 8)
            .unwrap();
        let slice = annexb_nals(&p)
            .unwrap()
            .into_iter()
            .find(|nal| nal[0] & 0x1f == 1)
            .unwrap();
        let mut decoder = VideoDecoder::new().unwrap();
        assert!(decoder.decode(&idr).unwrap().is_some());
        assert!(decoder.decode(&with_pps_one(pps, 0)).unwrap().is_none());
        assert!(decoder.decode(&with_pps_one(slice, 2)).unwrap().is_some());
    }

    #[test]
    fn decodes_access_unit_with_multiple_idr_slices() {
        let config = EncoderConfig::new()
            .profile(Profile::Baseline)
            .max_frame_rate(FrameRate::from_hz(15.0))
            .rate_control_mode(RateControlMode::Off)
            .skip_frames(false)
            .num_threads(1)
            .max_slice_len(600);
        let mut encoder = Encoder::with_api_config(OpenH264API::from_source(), config).unwrap();
        let rgb: Vec<u8> = (0..320 * 240 * 3)
            .map(|i| ((i * 73 + i / 17) % 256) as u8)
            .collect();
        let yuv = YUVBuffer::from_rgb8_source(RgbSliceU8::new(&rgb, (320, 240)));
        let encoded = encoder.encode(&yuv).unwrap().to_vec();
        assert!(
            annexb_nals(&encoded)
                .unwrap()
                .iter()
                .filter(|nal| nal[0] & 0x1f == 5)
                .count()
                > 1
        );
        let frame = VideoDecoder::new()
            .unwrap()
            .decode(&encoded)
            .unwrap()
            .unwrap();
        assert_eq!((frame.width, frame.height), (320, 240));
    }

    /// Build an Annex B baseline SPS fixture for coded and visible size checks.
    ///
    /// # Panics
    /// With overflow checks enabled, panics if either macroblock dimension is zero
    /// or the bottom crop is `u32::MAX`.
    fn baseline_sps(mb_width: u32, mb_height: u32, crop_bottom: u32) -> Vec<u8> {
        /// Append the unsigned Exp-Golomb prefix and value bits to the fixture.
        ///
        /// # Panics
        /// With overflow checks enabled, panics for `u32::MAX`.
        fn ue(bits: &mut Vec<bool>, value: u32) {
            let value = value + 1;
            let count = 32 - value.leading_zeros();
            bits.extend(std::iter::repeat_n(false, (count - 1) as usize));
            for shift in (0..count).rev() {
                bits.push(value & (1 << shift) != 0);
            }
        }
        let mut bits = Vec::new();
        ue(&mut bits, 0); // SPS ID
        ue(&mut bits, 0); // log2_max_frame_num_minus4
        ue(&mut bits, 0);
        ue(&mut bits, 0); // POC type, log2_max_pic_order_cnt_lsb_minus4
        ue(&mut bits, 1);
        bits.push(false); // one reference, no frame gaps
        ue(&mut bits, mb_width - 1);
        ue(&mut bits, mb_height - 1);
        bits.extend([true, true, crop_bottom > 0]);
        if crop_bottom > 0 {
            for crop in [0, 0, 0, crop_bottom] {
                ue(&mut bits, crop);
            }
        }
        bits.extend([false, true]); // no VUI, RBSP stop bit
        while bits.len() % 8 != 0 {
            bits.push(false);
        }
        let mut nal = vec![0x67, 66, 0xc0, 30];
        for chunk in bits.chunks_exact(8) {
            nal.push(
                chunk
                    .iter()
                    .fold(0u8, |acc, bit| (acc << 1) | u8::from(*bit)),
            );
        }
        let mut unit = vec![0, 0, 0, 1];
        unit.extend(nal);
        unit
    }

    #[test]
    fn rejects_oversized_sps_before_native_decoder_is_created() {
        let mut decoder = VideoDecoder::new().unwrap();
        assert!(decoder.decode(&baseline_sps(120, 68, 4)).unwrap().is_none()); // 1920×1080 visible
        assert!(decoder.decode(&baseline_sps(121, 68, 4)).is_err());
        assert!(decoder.decode(&baseline_sps(120, 69, 12)).is_err());
        assert!(decoder.decode(&baseline_sps(120, 68, 0)).is_err()); // 1088 visible
        assert!(decoder.decoder.is_none());
    }

    /// Verify that invalid NAL headers and malformed parameter sets surface
    /// as recoverable decoder errors.
    #[test]
    fn handles_malformed_annexb_without_panicking() {
        let mut decoder = VideoDecoder::new().unwrap();
        for unit in [
            &[][..],
            &[0, 0, 1][..],
            &[0, 0, 1, 0xe7, 1][..],
            &[0, 0, 1, 0x67, 0, 0, 3][..],
            &[0, 0, 1, 0x67, 66, 0, 30, 0][..],
            &[0, 0, 1, 0x6f, 66, 0, 30, 1][..],
        ] {
            assert!(decoder.decode(unit).is_err());
        }
    }
}
