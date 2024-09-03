# HRIS CSV Import Example

This sample connector reads employee data from a CSV file to populate a Human Resources Information System (HRIS) Open Authorization API (OAA) template. Veza uses the employee data from the HRIS to enrich user Identities with employee information like titles, managers, departments and employment status.

For more information on the OAA HRIS Template see the Veza User Guide.

## Overview

The connector reads from a CSV file containing the employee information rows. The connector can easily be modified to use different column headings and can serve as a starting point for importing a report from a specific HRIS technology. Alternatively, the report column headers can be edited to match this importer.

The expected column headers are:
```
employee_number,account,first_name,last_name,display_name,preferred_name,work_email,employment_status,active,title,department,manager,start_date,date_terminated,employment_type,tshirt_size
```

The `example.csv` can serve as a reference and starting point.

When the connector is run an HRIS employee is created for each row in the csv. HRIS Groups for departments are automatically created based on the employee data.

## Customizing the Connector

At the top of the `hris_import_csv.py` are variables for `HRIS_VENDOR`, `HRIS_VENDOR_URL` and `HRIS_ICON_B64`. These can be updated to change from the default example values to the HRIS vendor information.

Customizing columns names and adding columns can be done by editing the values in the `load_users` method.

The connector includes one example of setting a custom property on employees for `tshirt_size`. Custom properties must be defined with a type before they can be set. For more information see the developer documentation in the Veza User Guide.

## Running the Connector

### Veza Setup Instructions

This connector requires a valid Veza API Key to interact with your Veza instance.

1. Generate an API Key for your Veza user. For detailed instructions consult the Veza User Guide.

### Install requirements

Install the Python requirements. This step is only necessary the first time. For more information on running Python see [Running Veza Python Scripts](../../docs/Running_Veza_Python_Scripts.md)

```
pip install -r requirements.txt
```

### Run the Importer

1. Export the Veza API Key

   ```
   export VEZA_API_KEY="Zdkemfds..."
   ```

   Or configure a `.env` file for [`python-dotenv`](https://pypi.org/project/python-dotenv/): Use the provided sample `.env.sample` as a guide. 


2. Run the importer. Provide the path to the CSV file to import

    ```
    ./hris_import_csv --veza-url https://example.vezacloud.com report_export.csv
    ```