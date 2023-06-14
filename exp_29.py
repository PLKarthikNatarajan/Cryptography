import numpy as np


def sha3_lane_condition():
    state = np.zeros((5, 5, 64), dtype=np.uint64)
    capacity_size = 1600 - 2 * 1024  # Capacity size in bits
    lane_condition_met = False
    round_count = 0

    while not lane_condition_met:
        round_count += 1

        lane_condition_met = np.all(np.any(state[:, :, :capacity_size // 64] != 0, axis=2))

    return round_count


rounds = sha3_lane_condition()
print("Number of rounds until all lanes in capacity have at least one nonzero bit:", rounds)
