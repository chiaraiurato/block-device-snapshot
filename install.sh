#!/bin/bash

# This script runs the make commands to clean, build, create a single file system, and mount the file system.

# Run make clean
echo "Running make clean..."
make clean-fs
make unmount-fs
make rmmod-fs
make clean

# Run make all
echo "Running make all..."
make all

# Run make create_singlefilefs
echo "Creating single file system..."
make create-singlefilefs

# Run make run-user
# echo "Running user..."
# make run-user

# Run make mount-fs
# echo "Mounting file system..."
# make mount-fs

echo "install.sh completed successfully."
