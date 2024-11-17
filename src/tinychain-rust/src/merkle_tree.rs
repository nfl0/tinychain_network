use blake3;

pub struct MerkleTree {
    leaves: Vec<[u8; 32]>,
}

impl MerkleTree {
    pub fn new() -> Self {
        MerkleTree { leaves: Vec::new() }
    }

    pub fn append(&mut self, data: &[u8]) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(data);
        self.leaves.push(hasher.finalize().as_bytes().clone());
    }

    pub fn root_hash(&mut self) -> [u8; 32] {
        if self.leaves.is_empty() {
            return [0u8; 32];
        }

        while self.leaves.len() > 1 {
            let mut new_leaves = Vec::new();
            for i in (0..self.leaves.len()).step_by(2) {
                let left_hash = self.leaves[i];
                let right_hash = if i + 1 < self.leaves.len() {
                    self.leaves[i + 1]
                } else {
                    self.leaves[i]
                };
                let mut hasher = blake3::Hasher::new();
                hasher.update(&left_hash);
                hasher.update(&right_hash);
                new_leaves.push(hasher.finalize().as_bytes().clone());
            }
            self.leaves = new_leaves;
        }

        self.leaves[0]
    }
}
