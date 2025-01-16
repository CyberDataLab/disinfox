# 🦊 DISINFOX (DISINFOrmation threat eXchange)

DISINFOX is an open-source threat intelligence exchange platform focused in the sharing of disinformation incidents.



## 🧱 Installation and deployment

First, clone the repository:

```bash
git clone https://github.com/CyberDataLab/disinfox
cd disinfox
```

Now, make a copy of the `example.env` file and name it `.env` and **change the `changeme` values**:

```bash
cp example.env .env
```

There are several ways of setting up DISINFOX, however, it is recommended to use the `setup.sh`, which runs the platform with a demo configuration.

```bash
bash setup.sh
```

This bash file will include a default user + the incidents available in the dataset, and will automatically launch the docker environment. You can use the `--destroy` flag to destroy the database and redo the setup.

## 👽 Other deployments

You can also run the platform _empty_ by just runnin (if setup.sh was run, the database volume should be erased):

```bash
docker compose up
```

or, if you want to run the readonly version where no changes can be performed, use:

```bash
docker compose -f docker-compose-readonly.yaml
```

the docker-compose files with `-dev` variants are recommended if you intend to make changes in the code.

## 🕹️ Use

After performing the installation, the DISINFOX's web page is available at <http://localhost/> by default or at the port established in the `FRONTEND_EXTERNAL_PORT` at the `.env` file.




