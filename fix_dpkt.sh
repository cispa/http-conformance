#!/bin/bash

# Get the virtual environment python path using poetry
python_path=$(poetry run which python)

# Get the Python version from the path
python_version=$(echo "$python_path" | egrep -oe "3.\d+")


# Construct the relative file path
relative_path=$(dirname "$python_path")"/../lib/python$python_version/site-packages/dpkt/http.py"

echo $relative_path


# Patching the file based on the provided instructions
sed -i '' '103s/args\[0\]/args[0], **kwargs/' "$relative_path"
sed -i '' '178s/unpack(self, buf)/unpack(self, buf, **kwargs)/' "$relative_path"
sed -i '' '232s/unpack(self, buf)/unpack(self, buf, head_response=False, **kwargs)/' "$relative_path"
sed -i '' '252s/^/        if head_response:\n            is_body_allowed = False\n/' "$relative_path"


echo "File patched successfully!"
