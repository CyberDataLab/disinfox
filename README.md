# 🦊 DISINFOX (DISINFOrmation Threat eXchange)

DISINFOX is an **open-source threat intelligence exchange platform** designed to structure, analyze, and share **disinformation incidents** just like cybersecurity threats. By using **Cyber Threat Intelligence (CTI) standards and methodologies**, DISINFOX ensures **interoperability, automation, and structured analysis**, enabling seamless integration with existing CTI tools.  

![DISINFOX homepage](imgs/homepage.png)

## ✨ Key Features  

- 📡 **Real-time disinformation intelligence exchange**  
- 🔍 **Structured data representation using STIX2**  
- 🖥️ **User-friendly web interface for managing incidents**  
- 📊 **Interactive visualizations and entity correlation**  
- 🔗 **Interoperability with CTI platforms (e.g., OpenCTI)**  
- 📡 **RESTful Public API for programmatic access**  
- 🐳 **Dockerized deployment for easy setup**  

---

## 🧱 Installation & deployment  

1. **Clone** the repository:

    ```bash
    git clone https://github.com/CyberDataLab/disinfox
    cd disinfox
    ```

2. **Copy the example environment file** and update the necessary values. **Please, modify the `changeme` values**:

    ```bash
    cp example.env .env
    ```

3. **Run it!:**  The recommended way to set up DISINFOX is via the `setup.sh` script, which deploys a demo configuration:

    ```bash
    bash setup.sh
    ```

This script:
✔️ Creates a default user
✔️ Loads a dataset of disinformation incidents
✔️ Automatically starts the Docker environment

Use `--destroy` to reset the database and reinitialize the setup.

## 👽 Alternative deployments

Run an empty instance without preloaded data:

```bash
docker compose up
```

Or deploy a read-only version where no modifications can be made:

```bash
docker compose -f docker-compose-readonly.yaml up
```

For development, use `-dev` variants of the Docker Compose files.

---

## 🕹️ Using DISINFOX

After installation, **DISINFOX's web interface** will be available at:  
📍 **<http://localhost/>** (or the port set in `FRONTEND_EXTERNAL_PORT` in `.env`)  

Log in with the default credentials (if not modified):  
📧 `changeme@example.com` / 🔑 `changeme`  

### 📰 Incident management  

The **Incidents** page provides a structured view of all reported disinformation incidents and a search bar to quickly find specific incidents. 

![DISINFOX disinformation incident listing](imgs/listing.png)

Clicking on an incident reveals details such as:  
✔️ Title & description  
✔️ Threat actor & affected countries  
✔️ Identified **DISARM TTPs**  
✔️ Interactive **STIX2 graph visualization**  
✔️ Export options (**PDF, Word, JSON**)  

![Disinformation incident detail](imgs/incident-detail.png)

Users can explore related **Threat Actors** and their associated incidents.  

![Threat Actor detail](imgs/threat-actor-detail.png)

### 👤 User profile & API Key  

The **Profile** page allows users to:  
✔️ View their account details  
✔️ Retrieve their **API key** for automated access  
✔️ Manage favorite incidents  

![Profile section](imgs/profile.png)

---

## 📚 Public API

DISINFOX provides a public API to obtain the new objects created in the platform. The API is deployed by default at <http://localhost:8080/incidents> or at the port established in the `API_EXTERNAL_PORT` at the `.env` file.

To use the API, you need to authenticate with the API key provided in the _Profile_ page. The API key is unique to each user and can be regenerated at any time. The API key must be included in the `Authorization` header of the request. Also, is necessary to use the `newer_than` parameter to get the new incidents created/modified after the specified date. The date must be in the ISO 8601 format. The following is an example of a request to the API:

```http
GET /incidents?newer_than=2024-10-30T01:35:21.128381Z HTTP/1.1
Host: localhost:8080
Authorization: <API_KEY>
Accept: */*
```

If done correctly, the API will return a JSON object with the new incidents created/modified after the specified date. Here is an example of body of the response:

```json
{
 "incidents": [
  {
   "created": "2024-12-16T00:56:33.476896Z",
   "description": "This is the description",
   "first_seen": "2024-12-13T00:00:00Z",
   "id": "intrusion-set--fe842862-3fa6-5385-b001-17108193592b",
   "labels": [
    "incident",
    "disinformation"
   ],
   "modified": "2024-12-16T00:56:33.476896Z",
   "name": "This is our test yeah",
   "spec_version": "2.1",
   "type": "intrusion-set"
  },
  {
   "created": "2024-12-16T00:55:32.167569Z",
   "description": "This is the description",
   "first_seen": "2024-12-13T00:00:00Z",
   "id": "intrusion-set--86eba414-15d2-5e58-a299-dcbeb0a19607",
   "labels": [
    "incident",
    "disinformation"
   ],
   "modified": "2024-12-16T00:55:32.167569Z",
   "name": "This is our test 2",
   "spec_version": "2.1",
   "type": "intrusion-set"
  },
  {
   "created": "2024-12-16T00:46:29.975529Z",
   "description": "This is the description",
   "first_seen": "2024-12-13T00:00:00Z",
   "id": "intrusion-set--3f6f81a1-a1c4-52b4-8622-612d64831c70",
   "labels": [
    "incident",
    "disinformation"
   ],
   "modified": "2024-12-16T00:46:29.975529Z",
   "name": "This is our test",
   "spec_version": "2.1",
   "type": "intrusion-set"
  },
  {
   "created": "2024-11-30T01:35:21.154275Z",
   "description": "The Russian disinformation machine is spinning new and recycled narratives to claim that Ukraine is re-selling French weapon systems on the black market and ending up in Russian hands. This narrative aims to convince Western audiences that Ukraine is not to be trusted with sophisticated weapons supplied by the West while casting a shadow on France’s role in providing military aid. For Russian audiences, the narrative highlights Russian “military might” prevailing against the “powerless West.” For Ukrainians, the narrative is intended to raise fears that the West will stop providing weapon systems to Ukraine.",
   "first_seen": "2022-01-01T00:00:00Z",
   "id": "intrusion-set--c76fcb3f-e669-5062-957b-bdeeb69eb34f",
   "labels": [
    "incident",
    "disinformation"
   ],
   "modified": "2024-11-30T01:35:21.154275Z",
   "name": "Ukraine re-sold French howitzers for profit",
   "spec_version": "2.1",
   "type": "intrusion-set"
  },
        ...
}
```

---

## 🔄 OpenCTI Integration

DISINFOX features a **custom OpenCTI connector**, allowing seamless ingestion of disinformation incidents into OpenCTI for enhanced analysis and correlation.
You can find the repository here: <https://github.com/CyberDataLab/opencti-connector-disinfox>.

## 📖 Citation

If you use DISINFOX in your research, please cite our work ❤️:

```bibtex
@misc{gonzález2025interoperablerepresentationsharingdisinformation,
      title={Toward interoperable representation and sharing of disinformation incidents in cyber threat intelligence}, 
      author={Felipe Sánchez González and Javier Pastor-Galindo and José A. Ruipérez-Valiente},
      year={2025},
      eprint={2502.20997},
      archivePrefix={arXiv},
      primaryClass={cs.CR},
      url={https://arxiv.org/abs/2502.20997}, 
}
```


## 📢 Contributing

Contributions are welcome! Feel free to **submit issues, request features, or contribute code**.  

For discussions and collaboration, you can mail any of the maintainers.

## 📜 License

DISINFOX is **open-source** under the **MIT License**. See the `LICENSE` file for details.

## 🚀 Future Plans

- **Expand dataset** to include more real-world disinformation incidents.
- **Implementing future data models** proposed by [DAD-CDM](https://dad-cdm.org).
- **Enhance automation** with AI-based classification.
- **Improve interoperability** by implementing TAXII support.

---

With DISINFOX, we're bringing CTI methodologies to help tackle disinformation. **Give it a try! 🦊**
