# Microsoft-JSON-Web-Token-Extractor

A JSON Web Token is created in memory when connecting to Azure using PowerShell using the following command:

I wondered if I could extract the JSON Web Token from memory without dumping anything on disk to avoid a trigger from any Endpoint Detection and Response solution.

The result is a C# tool to extract all JSON Web Tokens found in memory used by PowerShell, including those found on disk.
