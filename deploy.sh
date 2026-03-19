#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}[1] Cleaning and compilation (Makefile)...${NC}"
make clean && make
if [ $? -ne 0 ]; then
    echo -e "${RED}Compilation failed. Check the errors above.${NC}"
    exit 1
fi

echo -e "${GREEN}[2] Removing old module...${NC}"
sudo rmmod sc_throttler 2>/dev/null

echo -e "${GREEN}[3] Inserting new module...${NC}"
sudo insmod sc_throttler.ko
if [ $? -ne 0 ]; then
    echo -e "${RED}Error loading the module. Recent dmesg output:${NC}"
    sudo dmesg | tail -n 10
    exit 1
fi

echo -e "${GREEN}[4] Verifying kernel logs...${NC}"
sudo dmesg | tail -n 5

echo -e "${GREEN}[DONE] Environment ready. Starting manual CLI...${NC}"
echo "----------------------------------------------------"
sudo ./user_cli