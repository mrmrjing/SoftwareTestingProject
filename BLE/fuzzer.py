import random

# Define possible states in the smart lock FSM.
class State:
    LOCKED = "Locked"
    AUTHENTICATING = "Authenticating"
    UNLOCKED = "Unlocked"
    ERROR = "Error"

# For this example, we simulate state transitions.
# In your real testing, the device’s response (or serial log) would tell you the new state.
def simulate_transition(current_state, command):
    """
    Simulate a state transition given a current state and a command.
    Command codes:
      0x00 -> Authenticate
      0x01 -> Open
      0x02 -> Close
    """
    if current_state == State.LOCKED:
        if command == 0x00:  # Authenticate command
            return State.AUTHENTICATING
        else:
            return State.ERROR  # Other commands are invalid from LOCKED
    elif current_state == State.AUTHENTICATING:
        if command == 0x01:  # Open command during authentication
            return State.UNLOCKED
        else:
            return State.LOCKED  # Go back if not proper
    elif current_state == State.UNLOCKED:
        if command == 0x02:  # Close command to lock again
            return State.LOCKED
        else:
            return State.ERROR  # Any other command leads to an error
    else:
        return State.ERROR

class Fuzzer:
    def __init__(self, initial_seed, energy=30, threshold=3):
        """
        :param initial_seed: A list representing a sequence of commands.
        :param energy: Number of mutations to apply per seed.
        :param threshold: Maximum count for a transition tuple to be considered 'interesting'.
        """
        self.seeds = [initial_seed]  # List of command sequences (each a list of int)
        self.energy = energy
        self.threshold = threshold
        self.transition_buckets = {}  # Dictionary to keep counts of transition tuples

    def update_bucket(self, from_state, to_state):
        key = (from_state, to_state)
        self.transition_buckets[key] = self.transition_buckets.get(key, 0) + 1

    def is_interesting(self, from_state, to_state):
        key = (from_state, to_state)
        count = self.transition_buckets.get(key, 0)
        # A transition is interesting if it hasn't been seen before or has been seen fewer times than the threshold.
        return count < self.threshold

    def mutate_input(self, seed):
        """
        Create a mutated version of the seed input.
        For simplicity, we change one command at a random index.
        """
        new_seed = seed.copy()
        idx = random.randrange(len(new_seed))
        # Randomly choose one of the valid command codes: 0x00, 0x01, or 0x02.
        new_seed[idx] = random.choice([0x00, 0x01, 0x02])
        return new_seed

    def fuzz(self, iterations=100):
        """
        Run the fuzzing loop for a set number of iterations.
        """
        for i in range(iterations):
            new_seeds = []
            for seed in self.seeds:
                # For each seed, perform several mutations as defined by the energy value.
                for e in range(self.energy):
                    mutated_seed = self.mutate_input(seed)
                    current_state = State.LOCKED  # Assume the lock always starts in LOCKED state.
                    interesting_found = False
                    # Process each command in the mutated sequence.
                    for command in mutated_seed:
                        next_state = simulate_transition(current_state, command)
                        self.update_bucket(current_state, next_state)
                        if self.is_interesting(current_state, next_state):
                            interesting_found = True
                        current_state = next_state
                    # If any transition in the mutated sequence was interesting, keep this seed for future fuzzing.
                    if interesting_found:
                        new_seeds.append(mutated_seed)
            # Add the new interesting seeds to the seed pool.
            if new_seeds:
                self.seeds.extend(new_seeds)
            # Optionally, print progress or bucket statistics every few iterations.
            if i % 10 == 0:
                print(f"Iteration {i}, Bucket counts: {self.transition_buckets}")
        return self.transition_buckets

if __name__ == "__main__":
    # Define an initial valid sequence:
    # For example, [0x00, 0x01, 0x02] corresponds to Authenticate -> Open -> Close.
    initial_seed = [0x00, 0x01, 0x02]
    
    # Create an instance of the fuzzer with an initial energy value of 30.
    fuzzer = Fuzzer(initial_seed, energy=30, threshold=3)
    
    # Run the fuzzing loop for a number of iterations.
    buckets = fuzzer.fuzz(iterations=100)
    
    print("\nFinal Transition Buckets:")
    for key, count in buckets.items():
        print(f"{key}: {count}")
