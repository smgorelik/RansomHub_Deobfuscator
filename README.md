# Garble Deobfuscation Script for RansomHub
This repository contains a script designed to deobfuscate most Garble-obfuscated Golang code within RansomHub. The script was specifically developed to aid in understanding obfuscated code by providing clarity and insight into its original form.

## Features
- Deobfuscates Garble-obfuscated Golang code.
- Compatible with IDA Pro 8.3.
- Utilizes Python 3.11 for script execution.
- Leverages Capstone 5.0.3 and Unicorn 2.1.0 libraries for binary analysis and emulation.
- Includes functionality to emulate instructions from a given address until reaching `runtime.slicebytetostring`.

## Prerequisites
Ensure the following are installed and configured before using this script:

1. **IDA Pro 8.3**: This script is tested on IDA Pro 8.3.
2. **Python 3.11**: The script was tested on Python 3.11.
3. **Capstone 5.0.3**: Install the Capstone library for disassembly support:
   ```
   pip install capstone==5.0.3
   ```
4. **Unicorn 2.1.0**: Install the Unicorn library for emulation support:
   ```
   pip install unicorn==2.1.0
   ```

Place the script in your IDA Pro plugins folder or load it directly in IDA.

## Additional Feature: Instruction Emulation to `runtime.slicebytetostring`
An additional file, `emulate_single_slicestring.py`, is included. This script enables emulating instructions from a given input address until it encounters the `runtime.slicebytetostring` function call. This is particularly useful for extracting and analyzing decrypted strings during the execution flow.

### Usage of `emulate_to_runtime.py`
1. Load the `emulate_single_slicestring.py` script into IDA Pro.
2. Call the function with the following parameters:
   ```python
   emulate_single_slicestring(start_addr, slice_addr, max_instructions=0x100)
   ```
   - `start_addr`: The address to start emulation from.
   - `runtime_addr`: The address of `runtime.slicebytetostring`.
   - `max_instructions`: (Optional) Maximum number of instructions to execute before stopping (default is 0x100).
3. The function will:
   - Print each instruction being executed.
   - Stop when it encounters a call to `runtime.slicebytetostring`.
   - Print the decrypted string (if applicable).

## Inspiration
This project was inspired by the detailed analysis and research shared in Bandit Stealer Garble De-Obfuscation (https://research.openanalysis.net/bandit/stealer/garble/go/obfuscation/2023/07/31/bandit-garble.html). The research served as a foundation for understanding and addressing the challenges posed by Garble obfuscation.

## Contributing
Contributions are welcome! If you encounter issues or have improvements, feel free to open an issue or submit a pull request.

## License
This project is licensed under the MIT License. See the LICENSE file for details.
