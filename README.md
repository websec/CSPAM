![CSPAM-logo](./img/cspam.png)

# CSPAM
Send Spoofed Telemetry Data / Violation Reports to CSP Policy Reporting Endpoint - Spoofer &amp; Spammer Utility

## Proof of Concept: Misusing CSP Policy Reporting Uri Directives

CSPAM is explicitly designed as a proof-of-concept tool to demonstrate how Content Security Policy (CSP) reporting mechanisms can be exploited. The `report-uri` and `report-to` directive in CSP allows administrators to specify where the browser should send reports about policy violations. While intended for security monitoring and mitigation, this feature can be targeted by malicious actors using tools like CSPAM.

### Key Exploits Demonstrated by CSPAM:

- **Endpoint Overload:** CSPAM can flood a CSP report endpoint with a high volume of forged reports. This deliberate overload can strain the endpoint's resources, potentially leading to denial of service if the endpoint is not scaled to handle such loads.

- **False Alarms:** By generating reports that mimic various types of CSP violations, CSPAM can create a slew of false alarms. Security teams may waste valuable resources investigating these non-existent threats, diverting attention from real security issues.

- **Exhausting Resource Limits:** Many CSP reporting services offer a limited number of free reports. CSPAM can be used to quickly exhaust these limits, imposing financial burdens or functional restrictions on the victim's reporting service.

Example of an Attack on a Csper.io Endpoint:

![CSP-Attack](./img/CSPSpoofingAttack.png)

### Implications

This tool illustrates the vulnerability of CSP reporting endpoints to spam and malicious interference. Organizations must ensure their CSP reporting infrastructure is robust enough to handle unexpected surges in reports and is equipped with mechanisms to filter out illegitimate reports. Security teams should also be aware of the potential for such tools to be used against their systems and prepare accordingly.

### History
Apperently the issue with these directives have been known for a while now, years actually...
However nobody seems to have made any Proof-of-Concept yet on how a CSP-Policies could be exploited in practice, hopefully this script will help to bring some more awareness to this topic.

### Conclusion
Please do not assume CSP is obsolete, it is still a very robust security measure and we strongly advise everyone to implement this. just be cautious regarding the implementation of the directives `report-uri` and `report-to` , ideally the reporting
endpoints should verify that the origin of the requests is actually the domain reporting.

## Disclaimer

CSPAM is intended for use by security researchers and professionals in controlled environments to test the resilience of CSP implementations against misuse. This tool should only be used with explicit permission on systems where such testing is authorized. Misuse of this tool can lead to unintended legal and ethical issues.

## Support Us
If you like our software, than you can show your support by giving this repo a star on GitHub and Follow us on social media for more cool releases:

https://www.linkedin.com/company/websecbv/

https://twitter.com/websecnl

https://facebook.com/websec
