#! /usr/bin/env ruby
###########################################################################
#
# [+] Description: This script interacts with a defined Nexpose Security Console's
# API to generate tailored asset & vulnerability reports using SQL Queries
# [+] Use Case: Automatically dump tailored reports for each asset or site in your Nexpose
# installation
#
#                          ~ author: nxkennedy ~
###########################################################################

#******** Usage ********#
# ruby nexpose-automate_reports.rb
#**********************#



require 'nexpose'
require 'rubygems'
require 'pp'
require 'yaml'
require 'csv'
include Nexpose



# ###########   Login method  ####################
# Read config from yaml file
config = YAML.load(File.read("config/nexpose.yml"))["server_config"]
@nsc = Connection.new(config["host"], config["username"], config["password"])
@nsc.login
##################################################

# Action to take on every line of csv file with header row
def process(report)
    puts "Code to process csv goes here for #{report}"

#  CSV.foreach(report, headers: true) do |row|
# **** actions here are operated on every row in the csv ****
#    puts row.inspect
#  end
end


######### Where the magic is. You've got report naming, sql query, & time monitoring.
def adhoc_report(site)
    start_time = Time.now

    report_name = "reports/#{site.name}.csv"
    puts "Generating #{report_name}. Be patient. Get some coffee."

    query = %q{WITH ip_counts_by_site AS (
    SELECT DISTINCT (da.ip_address), COUNT(DISTINCT ds.name) AS sites, array_to_string(array_agg(DISTINCT ds.name), ',') AS site_names, da.mac_address, da.host_name
    FROM dim_site ds
    JOIN dim_site_asset USING (site_id)
    JOIN dim_asset da USING (asset_id)
    GROUP BY ip_address, da.mac_address, da.host_name
    -- CT site_id) > 1
    )
    SELECT host_name, ip_address, mac_address, sites, site_names
    FROM ip_counts_by_site
    ORDER BY host_name}

    report_config = Nexpose::AdhocReportConfig.new(nil, 'sql', site.id)
    report_config.add_filter('version', '2.0.1')
    report_config.add_filter('query', query)
    report_output = report_config.generate(@nsc)

    end_time = Time.now

    File.open(report_name, "w+") do |file|
      file.write report_output
    end

    csv_output = CSV.parse(report_output.chomp, { :headers => :first_row })
    file_length = csv_output.entries.count

    #calculates duration for file creation
    ttg =  ( (end_time - start_time) / 60).round(1)
    puts "\t. . . Complete after #{ttg} minutes and is #{file_length} lines long!"
    report_name
end
###################################################


# Stores the output in an array and searches all sites
@output = []
# You can pull sites from the console with either a regex search
# by name or from a hardcoded array or names
#sites = @nsc.list_sites.select {|s| s.name.include?("foo")}
sites = ['foo-site',
'bar-site',
'foo2-site',
'bar2-site',
]
sites.each do |site|
    @output << adhoc_report(site)
end


# Output reports to the screen
@output.each do |report|
    process report
end
