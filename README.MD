## About
Obfuspy is a Python module for analyzing binary files especially to measure the effects of obfuscation. The initial goal of this work is to provide a CLI that process the .TEXT section of a binary and analyzes the size of the .TEXT section, the size of functions, counts the number of jump instructions, and calculates the entropy of the .TEXT section for additional processing.

After these initial goals are met new features will be added. If you have an idea for a feature please open an issue.

## Prerequisutes

Python3.8+
objdump

## Installation
For now download the project and unzip it then run `pip install -r requirements.txt`.
This will be uploaded to pypi on a later date.

## Usage
For now there is one CLI `obfustat.py`. This CLI takes a binary file as a positional argument and reports the size of the .TEXT section, the function name; counting both the total instructions and the number of jump instructions.

Give `python obfustat.py ./test_files/a.out` a shot.

## Documentation
As of yet there is none if you are curious take a look at the doc strings in helpers.py

## Roadmap
Please consult the issues board of this repository.

## Contributing
Contributors are always welcome and will be greatly appreciated.

    1. Fork the Project
    2. Create your Feature Branch `git checkout -b feature/AmazingFeature`
       (writing unit tests would be greatly appreciated and please also use type hints)  
    3. Commit your Changes `git commit -m 'Add some AmazingFeature'`
    4. Push to the Branch `git push origin feature/AmazingFeature`
    5. Open a Pull Request

## License
This Project is licensed under the Apache License Version 2.0