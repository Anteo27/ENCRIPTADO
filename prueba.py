with open('archivoPrueba.txt', 'r') as infile, open('aarchivoPrueba.txt', 'w') as outfile:
    data = infile.read()
    data = data.replace('\x00', '')
    outfile.write(data)