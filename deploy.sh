#!/bin/bash

# Colori per output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}[1] Pulizia e Compilazione...${NC}"
make clean && make
if [ $? -ne 0 ]; then
    echo -e "${RED}Compilazione fallita!${NC}"
    exit 1
fi

echo -e "${GREEN}[2] Rimozione vecchio modulo (se presente)...${NC}"
# Ignora errore se il modulo non era caricato
sudo rmmod sc_throttler 2>/dev/null

echo -e "${GREEN}[3] Inserimento nuovo modulo (Bare Metal Mode)...${NC}"
sudo insmod sc_throttler.ko
if [ $? -ne 0 ]; then
    echo -e "${RED}Errore nel caricamento del modulo! Controlla dmesg.${NC}"
    sudo dmesg | tail -n 10
    exit 1
fi

echo -e "${GREEN}[4] Verifica PTE e Caricamento...${NC}"
# Mostra solo i messaggi del nostro driver
sudo dmesg | grep "SC_THROTTLER" | tail -n 5

echo -e "${GREEN}[DONE] Modulo pronto. Ora avvia la CLI.${NC}"