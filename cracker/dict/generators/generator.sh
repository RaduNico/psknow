#!/bin/bash

./date_generator.py 1900 2100

./date_generator.py 1900 2100 "-./\\:_" yes

./date_generator.py 0 1900

./date_generator.py 2100 10000

./date_generator.py 0 1900 "-./\\:_"

./date_generator.py 2100 10000 "-./\\:_"

