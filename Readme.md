# CTng: Certificate and Revocation Transparency

This is a Proof of Concept/Prototype code for CTng. Each entity can be found in their corresponding folder, and additional details can be found in separate documentation.

## Hardware Requirements

- Intel 12th gen core i7 12700K or above
- 32 GB of system memory or above

## Software Requirements

- WSL2 11.1.0ubuntu4 Operating System
- Visual Studio Code with Golang extension
- Golang 1.19
- g++ (Ubuntu 11.3.0-1ubuntu1~22.04.1) 11.3.0
- tmux terminal multiplexer

## Running Tests Locally

### Step 1: Generate Configs for CAs, Loggers, Monitors, and Gossipers

1.1 Create a separate Go file with just the main function, import CTngV2/Gen

1.2 Create a `test.go` file and a script file to configure more variables that have not been initialized by the streamlined Config generation (Examples can be found under `tests/Experiments` or `tests/networktests`)

1.3 Create a `result_test.go` file to make sure the results meet our expectations (Examples can be found under the same folders as 1.2)

### Step 2: Run the Experiment

2.1 Execute the script, e.g., `sh 1144.sh`, and let it run for at least 3 periods (Note: We slice the time string to get the period number; wait a few minutes if the current time is over 57 min, e.g., 5:57 pm)

### Step 3: Run the Evaluation Script

3.1 Run the command `go test` to check if everything behaves as normal and check the convergence time

## Additional Information

Alternatively, one can also check some demo test runs under the Action tab where all previous workflow runs can be found, as well as the workflow files themselves.
