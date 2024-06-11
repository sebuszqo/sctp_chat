# Użyj oficjalnego obrazu Pythona jako bazy, który również zawiera podstawowe narzędzia systemowe
FROM python:3.10

# Zainstaluj Golang
RUN wget https://golang.org/dl/go1.18.3.linux-amd64.tar.gz \
    && tar -xvf go1.18.3.linux-amd64.tar.gz \
    && mv go /usr/local \
    && rm go1.18.3.linux-amd64.tar.gz
ENV PATH="${PATH}:/usr/local/go/bin"

# Ustaw katalog roboczy
WORKDIR /app

# Skopiuj pliki z twojego lokalnego katalogu do obrazu
COPY . /app

# Polecenie uruchamiające kontener
CMD ["bash"]