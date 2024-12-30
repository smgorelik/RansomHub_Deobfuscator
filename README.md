# Garble Deobfuscation Script for RansomHub

This repository contains a script designed to deobfuscate most Garble-obfuscated Golang code within RansomHub. The script was specifically developed to aid in understanding obfuscated code by providing clarity and insight into its original form.

# Features

* Deobfuscates Garble-obfuscated Golang code.

* Compatible with IDA Pro 8.3.

* Utilizes Python 3.11 for script execution.

* Leverages Capstone 5.0.3 and Unicorn 2.1.0 libraries for binary analysis and emulation.

# Prerequisites

* Ensure the following are installed and configured before using this script:

* IDA Pro 8.3: This script is tested on IDA Pro 8.3.

* Python 3.11: The script was tested on Python 3.11.

* Capstone 5.0.3: Install the Capstone library for disassembly support.

```pip install capstone==5.0.3```

Unicorn 2.1.0: Install the Unicorn library for emulation support.

```pip install unicorn==2.1.0```


Place the script in your IDA Pro plugins folder or load it directly in IDA.

# Inspiration

This project was inspired by the detailed analysis and research shared in Bandit Stealer Garble De-Obfuscation (https://research.openanalysis.net/bandit/stealer/garble/go/obfuscation/2023/07/31/bandit-garble.html). 
The research served as a foundation for understanding and addressing the challenges posed by Garble obfuscation.

Contributing

Contributions are welcome! If you encounter issues or have improvements, feel free to open an issue or submit a pull request.

# License

This project is licensed under the MIT License. See the LICENSE file for details.
