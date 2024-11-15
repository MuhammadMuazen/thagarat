/*
    Made with hatred and vengence by Muhammad Muazen ;> Just Kidding
*/

use thagarat::{fetch, helper_functions, cve};

/*
    Action --> Main function
    Input --> None 
    Output --> None
    Calls --> From helper_functions.rs:
                helper_functions::simple_help_message(): to print the simple help message
                helper_functions::full_help_message(): to print the full help message
                helper_functions::is_valid_cve_name(cve_id: &str): to check if the CVE ID provided is valid or not
                check_used_options(args: Vec<String>, mandatory_param: &str): to check the options the user specifed in the command line
                cveid_specified_options(cve_data: &mut super::cve::CVE, options: HashMap<String, String>): to get the value of the options the user specifed
                build_cves_request(url: &mut String, options: HashMap<String, String>): to build the URL with the user specifed options
                are_avaliable_args(args: Vec<String>): to check if the all the provided options are valid

              From fetch.rs:
                fetch::fetch_cveid_data(url: &str): to fetch the CVE ID data from the shodan API
                fetch_cves_data(url: &str): to fetch the CVES data from the shodan API
              
              From cve.rs:
                CVE.formated_cve_table(): to print the formated table for the fetched CVE data
                CVE::new(): to create a new CVE struct
    Called In --> None
*/
#[tokio::main]
async fn main() {

    // Get the command line args
    let args: Vec<String> = std::env::args().collect();

    // Check if all the provided args are valid
    helper_functions::are_available_args(args.clone());

    // If the user provided no arguments to the program
    if args.len() <= 1 {
        
        println!("\n[!] Please provide the arguments!");
        println!("[+] Check the help message using the option: {{ --help }} or {{ -h }}\n");
        
        std::process::exit(-1);
    }

    // If the user used the { --help, -h } option
    if args.len() == 2 && (args[1] == "-h" || args[1] == "--help") {
        
        helper_functions::simple_help_message();
        std::process::exit(0)
    }
        
    // If the user used the { --full-help, -fh } option    
    if args.len() == 2 && (args[1] == "-fh" || args[1] == "--full-help") {

        helper_functions::full_help_message();
        std::process::exit(0);
    }

    // If the user provided the argument { --cve-id, -cid }
    if args.len() >= 3 && (args[1] == "--cve-id" || args[1] == "-cid") && helper_functions::is_valid_cve_name(&args[2]) {
        
        let shodan_cveid_url_api: String = "https://cvedb.shodan.io/cve/".to_string();
        // CVE struct to hold the values of the fetched data
        let mut cve_var: cve::CVE = cve::CVE::new();
        
        // Get the CVE ID data
        match fetch::fetch_cveid_data(format!("{}{}", shodan_cveid_url_api, &args[2]).as_str()).await {
            Ok(cve_data) => cve_var = cve_data,
            Err(e) => eprintln!("Error fetching data: {}", e)
        }
        
        // If the user provided only the CVE ID parameter without any other options
        if args.len() == 3 {
            // Print the CVE struct as formatted table
            cve_var.formated_cve_table();
            std::process::exit(0);

        } else if args.len() > 3 { // If the user provided options for the { --cve-id, -cid } parameter
            
            // Check the user used options
            let cve_id_options: std::collections::HashMap<String, String> = helper_functions::check_used_options(args, "cve-id");
            
            // Modify the CVE struct to match the user specifed options
            helper_functions::cveid_specified_options(&mut cve_var, cve_id_options, "cveid");
            
            // Print the CVE struct as formatted table
            cve_var.formated_cve_table();
            std::process::exit(0);
        }
    
    // If the user provided the { --cves, -cs } parameter
    } else if args.len() >= 2 && (args[1] == "--cves" || args[1] == "-cs") {
        
        let mut shodan_cves_api: String = "https://cvedb.shodan.io/cves".to_string();
        // Vector CVE struct to hold the values of the fetched data
        let mut cves_vec: Vec<cve::CVE> = Vec::new();

        // If the user provieded only the the parameter { --cves, -cs } without any other options
        if args.len() == 2 {

            // Get the CVEs Data
            match fetch::fetch_cves_data(format!("{}?limit=10", shodan_cves_api).as_str()).await {
                Ok(cves_data) => cves_vec = cves_data,
                Err(e) => eprintln!("Error fetching data: {}", e)
            }

            // Iterate on the Vector and for each CVE it as formatted table
            cves_vec.iter().for_each(|cve: &cve::CVE| cve.formated_cve_table());
            std::process::exit(0);

        } else if args.len() > 2 { // If the user provided options to the { --cves, -cs } parameter
            // Check the user used options
            let cves_options: std::collections::HashMap<String, String> = helper_functions::check_used_options(args, "cves");
            
            // Build the API URL to match the user specifed options
            helper_functions::build_cves_request(&mut shodan_cves_api, cves_options.clone());

            // Get the CVEs data
            match fetch::fetch_cves_data(&shodan_cves_api).await {
                Ok(cves_data) => cves_vec = cves_data,
                Err(e) => eprintln!("Error fetching data: {}", e)
            }
            
            // Iterate on the CVEs Vector
            cves_vec.iter_mut().for_each(|cve: &mut cve::CVE| {
                // Check the options the user specifed for the CVE IDs
                helper_functions::cveid_specified_options(cve, cves_options.clone(), "cves");

                // Print the CVE struct as formatted table
                cve.formated_cve_table();
            });

            std::process::exit(0);
        }
    
    } else { // If the user did not specify the right parameters or arguments

        println!("\n[!] Please provide the arguments and parameters!");
        println!("[+] Check the help message using the option: {{ --help }} or {{ -h }}\n");
        
        std::process::exit(-1);
    }
}
