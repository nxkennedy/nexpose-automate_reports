
# Nexpose Automated Report Generator

This script interacts with a Nexpose Security Console's API to generate tailored asset & vulnerability reports using SQL Queries

<table>
    <tr>
        <th>Version</th>
        <td>1.0.0</td>
    </tr>
    <tr>
       <th>Author</th>
       <td>Nolan Kennedy
    </tr>
    <tr>
        <th>Github</th>
        <td><a href="http://github.com/nxkennedy/nexpose-automate_reports">http://github.com/nxkennedy/nexpose-automate_reports</a></td>
    </tr>
</table>

## Use Case

Automatically dump tailored reports for each asset or site in your Nexpose installation using the Nexpose API

## Requirements
1. Rapid7 Nexpose Security Console
2. Tested using ruby 2.4.0 and nexpose-client gem 6.0.0

## Setup
1. Clone the repo

    `git clone https://github.com/nxkennedy/nexpose-automate_reports.git`

2. Install the nexpose-client gem

    `gem install nexpose`

3. In the directory where you cloned the repo, rename /config/example.yml to /config/config.yml
4. In your new config.yml file, change the 'host', 'username', and 'password'
variables to reflect the correct information relative to your Nexpose installation. Be sure to keep the singe quotes around your password.
THIS FILE WILL CONTAIN LOGIN CREDENTIALS. BE CAREFUL WHO YOU SHARE IT WITH.
5. Save and close the config file
6. Read the SQL-QUERIES.md file that came with the repo and select a query type
that suits your reporting needs. Highlight and copy just the SQL code.
7. Open the nexpose-automate_reports.rb script. Find the 'query' variable and
paste your code in. Should look like: query = q%{your sql code}
8. Save and close the script
9. Let 'er rip

     `ruby nexpose-api_reports.rb`

## Output
Progress is printed to terminal, reports are written to CSV in '/reports' directory
