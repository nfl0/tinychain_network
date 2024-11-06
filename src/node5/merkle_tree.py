import blake3

class MerkleTree:
    def __init__(self):
        self.leaves = []

    def append(self, data):
        hasher = blake3.blake3()
        hasher.update(data)
        self.leaves.append(hasher.digest())

    def root_hash(self):
        if len(self.leaves) == 0:
            return b''

        while len(self.leaves) > 1:
            new_leaves = []
            for i in range(0, len(self.leaves), 2):
                left_hash = self.leaves[i]
                right_hash = self.leaves[i + 1] if i + 1 < len(self.leaves) else self.leaves[i]
                combined_hash = blake3.blake3(left_hash + right_hash).digest()
                new_leaves.append(combined_hash)
            self.leaves = new_leaves

        return self.leaves[0]
