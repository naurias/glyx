use serde::{Deserialize, Serialize};

use crate::{ids, DeviceId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Hlc {
    pub wall_ms: u64,
    pub seq: u16,
    pub node: DeviceId,
}

impl Hlc {
    #[must_use]
    pub fn now(node: DeviceId) -> Self {
        Self {
            wall_ms: ids::wall_ms_now(),
            seq: 0,
            node,
        }
    }
    #[must_use]
    pub fn update(self, remote: Hlc, node: DeviceId) -> Self {
        let wall = ids::wall_ms_now().max(remote.wall_ms).max(self.wall_ms);
        let seq = if wall == self.wall_ms && wall == remote.wall_ms {
            self.seq.max(remote.seq).saturating_add(1)
        } else if wall == self.wall_ms {
            self.seq.saturating_add(1)
        } else if wall == remote.wall_ms {
            remote.seq.saturating_add(1)
        } else {
            0
        };
        Self {
            wall_ms: wall,
            seq,
            node,
        }
    }
}
