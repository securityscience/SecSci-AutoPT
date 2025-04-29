# Sec-Sci AutoPT

## Introduction
Sec-Sci AutoPT, an Automated Penetration Testing (AutoPT) framework, has undergone a remarkable evolution since its inception in 2017 as version 1 tailored for HP WebInspect. Transitioning to BurpSuite Pro in 2019 marked a strategic move, driven by considerations of cost-effectiveness and a desire for a more streamlined implementation.

The version 5 was released in July 2024. Sec-Sci AutoPT stands as a testament to continuous improvement. It caters to a broader user base with support for multiplatform operating systems, particularly MS Windows and Linux-based machines. The latest iteration boasts enhanced manageability, accelerated performance, an even more user-friendly implementation and heightened security through encryption for accounts, credentials, and certificates. A host of new features further enrich its capabilities, making it a cutting-edge solution in the field of penetration testing automation.

This open-source framework is a meticulously crafted proof of concept (POC), designed to simplify the intricate task of identifying and mitigating security vulnerabilities in applications and systems. Its strength lies in the seamless integration of potent tools such as BurpSuite Pro, Docker, Cucumber, Cypress, Selenium, Robot Framework, and Python. Together, they orchestrate a comprehensive and automated penetration testing workflow, ensuring a thorough assessment and discovery of potential weaknesses.

---

## Key Features and Functionality:
- **Automated Scanning**: The framework automatically sets the project to scan, initiating the automated scanning process using BurpSuite Pro. It allows for quick and accurate vulnerability assessments of web applications.
- **Continuous Integration**: Sec-Sci AutoPT is integrated into the build pipeline through a Continuous Integration and Continuous Delivery (CI-CD) pipeline. It efficiently fetches QA testing or Functionality testing automation packages from the repository and triggers the pen testing process as needed.
- **Versatile Testing Environment**: The framework ensures consistent and isolated testing environments by utilizing Docker containerization. This enables efficient deployment and management of different testing setups.
- **Customizable Automation**: The integration of Cucumber, Cypress, Selenium, and Robot Framework provides a customizable and extendable automation capability. It supports both API service calls functionality testing and UI functionality testing.
- **Security Assessment and Reporting**: The automated pen testing platform executes the QA acceptance testing, running the appropriate testing tools (e.g., Docker, Cucumber, Cypress, Selenium, Robot Framework, and/or Python) based on the project type. It allows for a thorough vulnerability scan process.
- **Efficient Vulnerability Management**: The framework allocates sufficient time for the vulnerability scan process to complete, ensuring comprehensive coverage of the target. Upon completion, it automatically closes Burp and archives old vulnerability reports for historical reference.
- **Clear and Informative Reporting**: Sec-Sci AutoPT generates comprehensive vulnerability reports. It also sends email notifications to relevant stakeholders, providing concise summaries of the security assessment results.

---

## Full Documentation
Visit: https://www.security-science.com/sec-sci-autopt

---

## License
This project is licensed under the [GPL-3.0 license] - see the [LICENSE.txt](LICENSE.txt) file for details.
