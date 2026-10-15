use std::cmp::Ordering;

use glyx_core::Hlc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderOrder {
    Older,
    Newer,
    Concurrent,
}

#[must_use]
pub fn cmp_header(a: Hlc, a_rev: u64, b: Hlc, b_rev: u64) -> HeaderOrder {
    match (a.wall_ms, a.seq).cmp(&(b.wall_ms, b.seq)) {
        Ordering::Less => HeaderOrder::Older,
        Ordering::Greater => HeaderOrder::Newer,
        Ordering::Equal if a.node != b.node => HeaderOrder::Concurrent,
        Ordering::Equal if a_rev < b_rev => HeaderOrder::Older,
        Ordering::Equal if a_rev > b_rev => HeaderOrder::Newer,
        Ordering::Equal => HeaderOrder::Concurrent,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictKind {
    FastForward,
    Stale,
    Concurrent,
    Tombstone,
}

#[must_use]
pub fn classify(
    local: Hlc,
    local_rev: u64,
    local_deleted: bool,
    remote: Hlc,
    remote_rev: u64,
    remote_deleted: bool,
) -> ConflictKind {
    if local_deleted || remote_deleted {
        return ConflictKind::Tombstone;
    }
    match cmp_header(local, local_rev, remote, remote_rev) {
        HeaderOrder::Older => ConflictKind::FastForward,
        HeaderOrder::Newer => ConflictKind::Stale,
        HeaderOrder::Concurrent => ConflictKind::Concurrent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use glyx_core::DeviceId;

    fn hlc(ms: u64, node_byte: u8) -> Hlc {
        Hlc {
            wall_ms: ms,
            seq: 0,
            node: DeviceId([node_byte; 16]),
        }
    }

    #[test]
    fn orders_headers() {
        assert_eq!(cmp_header(hlc(1, 0), 1, hlc(2, 0), 1), HeaderOrder::Older);
        assert_eq!(cmp_header(hlc(3, 0), 1, hlc(2, 0), 1), HeaderOrder::Newer);
        assert_eq!(
            cmp_header(hlc(2, 0), 1, hlc(2, 1), 1),
            HeaderOrder::Concurrent
        );
    }

    #[test]
    fn concurrency_smoke_two_writers() {
        let a = hlc(100, 1);
        let b = Hlc {
            wall_ms: 100,
            seq: 0,
            node: DeviceId([2; 16]),
        };
        assert_eq!(classify(a, 2, false, b, 2, false), ConflictKind::Concurrent);
        assert_eq!(
            classify(a, 1, false, hlc(200, 2), 1, false),
            ConflictKind::FastForward
        );
        assert_eq!(
            classify(hlc(300, 1), 1, false, hlc(200, 2), 1, false),
            ConflictKind::Stale
        );
        assert_eq!(classify(a, 2, true, b, 2, false), ConflictKind::Tombstone);
    }
}
