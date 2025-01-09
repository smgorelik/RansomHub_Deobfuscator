# Garble Deobfuscation Script for RansomHub
This repository contains a scripts designed to deobfuscate most Garble-obfuscated Golang code within RansomHub. The script was specifically developed to aid in understanding obfuscated code by providing clarity and insight into its original form.

![](https://github.com/smgorelik/RansomHub_Deobfuscator/blob/main/ungrable.gif)

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
An updated file, `emulate_single_slicestring.py`, is included. This script enables emulating instructions from a given input address until it encounters the `runtime.slicebytetostring` function call. This is particularly useful for extracting and analyzing decrypted strings during the execution flow.

### Usage of `emulate_single_slicestring.py`
1. Load the `emulate_single_slicestring.py` script into IDA Pro.
2. Call the function with the following parameters:
   ```python
   emulate_single_slicestring(
       start_address,
       slicebyte_addr,
       newobject_addr,
       growslice_addr,
       max_instructions=0x2000
   )
   ```
   - `start_address`: The address to start emulation from (e.g., the start of the obfuscation function or even mid-function).
   - `slicebyte_addr`: The address of the `runtime.slicebytetostring` function.
   - `newobject_addr`: **(New)** The address of the `runtime.newobject` function.
   - `growslice_addr`: **(New)** The address of the `runtime.growslice` function.
   - `max_instructions`: Maximum number of instructions to execute before stopping (default is `0x2000` for functions requiring extensive emulation).

3. The function will:
   - Print each instruction being executed.
   - Stop when it encounters a call to `runtime.slicebytetostring`.
   - Print the decrypted string.

## Inspiration
This project was inspired by the detailed analysis and research shared in Bandit Stealer Garble De-Obfuscation (https://research.openanalysis.net/bandit/stealer/garble/go/obfuscation/2023/07/31/bandit-garble.html). The research served as a foundation for understanding and addressing the challenges posed by Garble obfuscation.

## Contributing
Contributions are welcome! If you encounter issues or have improvements, feel free to open an issue or submit a pull request.

## License
This project is licensed under the MIT License. See the LICENSE file for details.
