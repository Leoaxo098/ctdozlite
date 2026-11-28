#![allow(dead_code)]
include!("../src/ingress.rs");

mod tests {
    use super::*;

    #[test]
    fn assembles_zalo_fragments_across_sequence_wrap() {
        let mut ingress = VideoIngress::new();
        assert!(ingress
            .push(65535, 1, false, &[0x1c, 0x80, 0, 0, 0, 1, 0x65])
            .unwrap()
            .is_none());
        assert_eq!(
            ingress.push(0, 1, true, &[0x1c, 0x40, 8, 9]).unwrap(),
            Some(vec![0, 0, 0, 1, 0x65, 8, 9])
        );
    }

    #[test]
    fn rejects_gap_and_discards_remaining_fragment() {
        let mut ingress = VideoIngress::new();
        ingress
            .push(1, 1, false, &[0x1c, 0x80, 0, 0, 1, 0x65])
            .unwrap();
        assert!(ingress.push(3, 1, true, &[0x1c, 0x40, 4]).is_err());
        assert!(ingress.push(4, 1, true, &[0x1c, 0x40, 5]).is_err());
        assert_eq!(
            ingress.push(5, 2, true, &[0, 0, 1, 0x65, 6]).unwrap(),
            Some(vec![0, 0, 1, 0x65, 6])
        );
    }

    #[test]
    fn assembles_multiple_nals_until_marker() {
        let mut ingress = VideoIngress::new();
        assert!(ingress.push(1, 1, false, &[0x67, 1]).unwrap().is_none());
        assert!(ingress.push(2, 1, false, &[0x68, 2]).unwrap().is_none());
        assert_eq!(
            ingress.push(3, 1, true, &[0x65, 3]).unwrap(),
            Some(vec![
                0, 0, 0, 1, 0x67, 1, 0, 0, 0, 1, 0x68, 2, 0, 0, 0, 1, 0x65, 3
            ])
        );
    }

    #[test]
    fn rejects_timestamp_change_during_fragment() {
        let mut ingress = VideoIngress::new();
        ingress.push(1, 1, false, &[0x7c, 0x85, 4]).unwrap();
        assert!(ingress.push(2, 2, true, &[0x7c, 0x45, 5]).is_err());
    }

    #[test]
    fn assembles_fu_a_and_validates_marker() {
        let mut ingress = VideoIngress::new();
        ingress.push(1, 1, false, &[0x7c, 0x85, 4]).unwrap();
        assert_eq!(
            ingress.push(2, 1, true, &[0x7c, 0x45, 5]).unwrap(),
            Some(vec![0, 0, 0, 1, 0x65, 4, 5])
        );
        assert!(ingress.push(3, 2, true, &[0x7c, 0x85, 4]).is_err());
    }

    #[test]
    fn rejects_malformed_stap_without_emitting_partial_nals() {
        let mut ingress = VideoIngress::new();
        assert!(ingress
            .push(1, 1, true, &[0x78, 0, 2, 0x67, 1, 0, 4, 0x68])
            .is_err());
        assert_eq!(
            ingress
                .push(2, 2, true, &[0x78, 0, 2, 0x67, 1, 0, 2, 0x68, 2])
                .unwrap(),
            Some(vec![0, 0, 0, 1, 0x67, 1, 0, 0, 0, 1, 0x68, 2])
        );
    }

    #[test]
    fn bounds_assembly_and_reset_drops_partial_data() {
        let mut ingress = VideoIngress::new();
        let mut huge = vec![1; 1024 * 1024];
        huge[0] = 0x65;
        assert!(ingress.push(1, 1, true, &huge).is_err());
        ingress
            .push(2, 2, false, &[0x1c, 0x80, 0, 0, 1, 0x65])
            .unwrap();
        ingress.reset();
        assert!(ingress.push(3, 2, true, &[0x1c, 0x40, 4]).is_err());
    }

    /// Check allocation capacity across repeated fragment appends, including
    /// the append that exceeds the access-unit limit.
    #[test]
    fn allocation_capacity_stays_bounded_while_appending_fragments() {
        let mut ingress = VideoIngress::new();
        let mut fragment = vec![1; 1001];
        fragment[..6].copy_from_slice(&[0x1c, 0x80, 0, 0, 1, 0x65]);
        ingress.push(0, 1, false, &fragment).unwrap();
        fragment[1] = 0;
        for sequence in 1..1049 {
            let _ = ingress.push(sequence, 1, false, &fragment);
            assert!(
                ingress.unit.capacity() <= 1024 * 1024,
                "allocated {}",
                ingress.unit.capacity()
            );
        }
    }
}
