/*
    Contains functions that are common in the project and used as helpers most of the times in the main.rs and cve.rs
    ^ This is the worst comment ever !!!
*/

use std::collections::HashMap;

/*
    Action --> Gets the name of the running executable.
    Input --> None
    Output --> the name of the running executable as a String
    Calls --> None
    Called In: helper_functions.rs:
                    full_help_message(): to get the name of the executable in the help message
                    simple_help_message(): to get the name of the executable in the help message

*/
fn get_exe_file_name() -> String {

    let exe_path: std::path::PathBuf = std::env::current_exe().expect("Failed to get current executable path");
    let exe_name: &std::ffi::OsStr = exe_path.file_name().expect("Failed to get executable name");
    let str_exe_name: &str = exe_name.to_str().expect("Failed to convert executable name to string");

    return str_exe_name.to_owned();
}

/*
    Action: check if the option is specifed in the arguments provided by the user and add them to a HashMap<String, String>
    Input --> command line arguments as &[String]
              option we want to check if the user provided as &str
              the hash map which holds the name of the option as key and the value true if it exists the hash map is of type &mut HashMap<String, String>
    Output --> None
    Calls --> None
    Called In --> helper_functions.rs: 
                    check_used_options(args: Vec<String>, mandatory_param: &str)
*/
fn insert_specified_options(args: &[String], option: &str, options_values: &mut std::collections::HashMap<String, String>) {
    
    if args.iter().any(|arg: &String| arg == option) {
        // Make the value of the specifed option equal true and add the option name as string without the '-'
        options_values.insert(option.to_string().replacen("-", "", 1), "true".to_string());
    }
}

/*
    Action --> Get the value of the CVES options mainly
    Input --> the arguments the user provided as &[String]
              the option we want to check it is value as &str
    Output --> the value of the option we specifed as Option<String>
    Calls --> None
    Called In --> helper_functions.rs:
                    check_used_options(args: Vec<String>, mandatory_param: &str)
*/
fn get_option_value(args: &[String], option: &str) -> Option<String> {

    if let Some(pos) = args.iter().position(|x| x == option) {
        args.get(pos + 1).cloned()
    } else {
        None
    }
}

/*
    Action --> Make the fileds of equal none of the user did not specify the option
    Input --> field we want to check as &mut Option<T>
              option we want to check if exists or not as Option<&String>
    Output --> None
    Calls --> None
    Called In --> helper_functions:
                    cveid_specified_options(cve_data: &mut super::cve::CVE, options: HashMap<String, String>, mandatory_param: &str)
*/
fn unset_if_option_missing<T>(field: &mut Option<T>, option: Option<&String>) {
    if field.is_some() && option.is_none() {
        *field = None;
    }
}

/*
    Action --> Used to check if the value of the option is not another option by checking if it started with '-' or not
    Input --> option value we want to test as &str
    Ouput --> result of the test as bool
    Calls --> None
    Called In --> helper_functions.rs:
                    build_cves_request(url: &mut String, options: HashMap<String, String>)
*/
fn does_not_start_with_hyphen(option_value: &str) -> bool {

    if option_value.starts_with("-") {

        println!("\n[!] Error: please specify a right values for the options");
        println!("[+] Check the help message using the option: {{ --help }} or {{ -h }}\n");
        
        return false;
    }

    return true;
}

/* 
    Action --> used to check if the options { -skip } and { -limit } is a number bigger than zero
    Input --> option value we want to test as &String
              option name we want to test it's value as &str
    Output --> ture if the test passed as bool
    Calls --> None
    Called In --> helper_functions.rs:
                    build_cves_request(url: &mut String, options: HashMap<String, String>)
*/
fn is_valid_unsigned_num(option_value: &String, option_name: &str) -> bool {
    
    if option_value.parse::<u32>().is_ok() {
        
        return true;
    
    } else {
        
        println!("\n[!] Error: the value of the option {{ {} }} should be a number bigger than zero!", option_name);
        println!("[+] Check the help message using the option: {{ --help }} or {{ -h }}\n");
        
        return false;
    }
}

/*
    Action --> Check if the value of the options { -start-date } and { -end-date } have the format YYYY-MM-DDTHH:MM:SS
    Input --> option value we want to test as &str
              name of the option we want to test against as &str
    Output --> true if passed the test as bool
    Calls --> None
    Called In --> helper_functions.rs:
                    build_cves_request(url: &mut String, options: HashMap<String, String>)
*/
fn is_valid_date_time(option_value: &str, option_name: &str) -> bool {
    
    let re: regex::Regex = regex::Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$").unwrap();
    if re.is_match(option_value) {
        
        return true;
    
    } else {

        println!("\n[!] Error: the value of the option {{ {} }} should have the format YYYY-MM-DDTHH:MM:SS", option_name);
        println!("[+] Check the help message using the option: {{ --help }} or {{ -h }}\n");
        
        return false;
    }
}

/*
    Action --> Check if all the command line arguments are avaliable otherwise exit the process
    Input --> arguments of the command line as Vec<String>
    Output --> None
    Call --> None
    Called In --> main.rs: Main function
*/
pub fn are_available_args(args: Vec<String>) {

    let available_options: Vec<String> = vec![
        "-id".to_string(), "-summary".to_string(), "-cvss-version".to_string(), "-cvss-v2".to_string(),
        "-cvss-v3".to_string(), "-epss".to_string(), "-kev".to_string(), "-ranking-epss".to_string(),
        "-propose-action".to_string(), "-ransomware-campaign".to_string(), "-references".to_string(),
        "-published-time".to_string(), "-cpes".to_string(), "-is-kev".to_string(), "-sort-by-epss".to_string(),
        "-product".to_string(), "-skip".to_string(), "-limit".to_string(), "-start-date".to_string(),
        "-end-date".to_string(), "--cves".to_string(), "-cs".to_string(), "--cve-id".to_string(),
        "-cid".to_string(), "--full-help".to_string(), "-fh".to_string(), "--help".to_string(), "-h".to_string()
    ];

    // Filter only the arguments that start with "-" and check if they are in available options
    let invalid_args = args.iter().filter(|arg: &&String| arg.starts_with("-") && !available_options.contains(arg));

    // If any invalid argument is found, print error and exit
    if invalid_args.count() > 0 {
        
        println!("\n[!] Please provide the right arguments and options!");
        println!("[+] Check the help message using the option: {{ --help }} or {{ -h }}\n");
        
        std::process::exit(1);
    }
}

/*
    Action --> Check if the CVE-ID is valid name
    Input --> cve_id representing the CVE ID we want to check as &str
    Output --> true if the provided argument have the right format for a CVE ID else print help message and exit the process
    Calls --> Nothing
    Called in --> main.rs
*/
pub fn is_valid_cve_name(cve_id: &str) -> bool {

    let re: regex::Regex = regex::Regex::new(r"^CVE-\d{4}-\d{4,}$").unwrap();

    if re.is_match(cve_id) {
        return true;
    } else {
        println!("[!] Please enter a valid CVE ID!");
        std::process::exit(-1);
    }
}

/*
    Action --> Printing the full help message
    Input -> Nothing
    Output --> Nothing
    Calls --> From helper_functions.rs:
                get_exe_file_name(): to get the name of the executable file
    Called in --> main.rs: main function
*/
pub fn full_help_message() {

    let executable_file_name: String = get_exe_file_name();

    println!(r#"
       ______________________________________________________________
      |~|~|~|~|~|~|~|~|~|~|~|~|~|THAGARAT|~|~|~|~|~|~|~|~|~|~|~|~|~|~| 
       ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
     _________________________________________________________________
    |OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO|
    |_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|
    |/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/|
    |  Automate The Shodan CVE API To Get The Latest CVEs Information |
    |\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\|
    |_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|_|
    |OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO|
     ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
[i] Usage:

        {} [mandatory parameters] [options]

[i] Mandatory Parameters:

        --cve-id, -cid <CVE-ID>  [options]  Retrieve information for specific CVE ID.
        --cves, -cs              [options]  Retrieve information for all available CVEs.
        --help, -h                          Print the simple help message
        --full-help, -fh                    Print the full help message

[i] Options:

        [+] Options for both {{ --cve-id, -cid }} and {{ --cves, -cs }}:
            
            -id                             Return the id of the CVE
            -kev                            Return the KVE for the CVE
            -cpes                           Return the CPES for the CVE  
            -epss                           Return the EPSS of the CVE
            -cvss                           Return the CVSS for the CVE
            -cvss-v3                        Return the CVSS-V3 version for the CVE
            -cvss-v2                        Return the CVSS-V2 version for the CVE
            -summary                        Return the summary that describes the CVE
            -references                     Return the references for the CVE
            -ranking-epss                   Return the ranking EPSS for the CVE
            -cvss-version                   Return the CVSS version for the CVE
            -published-time                 Return the publish time for the CVE
            -propose-action                 Return the propose action for the CVE
            -ransomware-campaign            Return the ransomware campaign for the CVE
        
        [+] Options specifed for {{ --cves, -cs }}:
            
            -is-kev                         Returns only CVEs with the kev flag set to true.
            -sort-by-epss                   Sorts CVEs by the EPSS score in descending order
            -skip <number>                  Number of CVEs to skip in the result set
            -limit <number>                 The maximum number of CVEs to return in a single query
            -end-date   <date>              End date for filtering CVEs (inclusive, format YYYY-MM-DDTHH:MM:SS)
            -start-date <date>              Start date for filtering CVEs (inclusive, format YYYY-MM-DDTHH:MM:SS)
            -product <product_name>         Return the CVEs that have the product name

[i] Examples:
        
        [1] {} -cs
        [2] {} -cid CVE-CVE-2023-50071
        [3] {} --cve-id CVE-2024-6387 -id -kev -references
        [4] {} --cves -id -limit 10 -start-date 2023-10-01T12:01:44 -cpes -published-time

    "#, executable_file_name, executable_file_name, executable_file_name, executable_file_name, executable_file_name);

}

/*
    Action --> Printing simple the help message
    Input -> Nothing
    Output --> Nothing
    Calls --> From helper_functions.rs:
                get_exe_file_name(): to get the name of the executable file
    Called in --> main.rs: main function
*/
pub fn simple_help_message() {

    let executable_file_name: String = get_exe_file_name();

    println!(r#"

[i] Usage:

        {} [mandatory parameters] [options]

[i] Mandatory Parameters:

        --cve-id, -cid <CVE-ID>  [options]  Retrieve information for specific CVE ID.
        --cves, -cs              [options]  Retrieve information for all available CVEs.
        --help, -h                          Print the simple help message
        --full-help, -fh                    Print the full help message

[i] Options:

        [+] Options for both {{ --cve-id, -cid }} and {{ --cves, -cs }}:
            
            -id                             Return the id of the CVE
            -kev                            Return the KVE for the CVE
            -cpes                           Return the CPES for the CVE  
            -epss                           Return the EPSS of the CVE
            -cvss                           Return the CVSS for the CVE
            -cvss-v3                        Return the CVSS-V3 version for the CVE
            -cvss-v2                        Return the CVSS-V2 version for the CVE
            -summary                        Return the summary that describes the CVE
            -references                     Return the references for the CVE
            -ranking-epss                   Return the ranking EPSS for the CVE
            -cvss-version                   Return the CVSS version for the CVE
            -published-time                 Return the publish time for the CVE
            -propose-action                 Return the propose action for the CVE
            -ransomware-campaign            Return the ransomware campaign for the CVE
        
        [+] Options specifed for {{ --cves, -cs }}:
            
            -is-kev                         Returns only CVEs with the kev flag set to true.
            -sort-by-epss                   Sorts CVEs by the EPSS score in descending order
            -skip <number>                  Number of CVEs to skip in the result set
            -limit <number>                 The maximum number of CVEs to return in a single query
            -end-date   <date>              End date for filtering CVEs (inclusive, format YYYY-MM-DDTHH:MM:SS)
            -start-date <date>              Start date for filtering CVEs (inclusive, format YYYY-MM-DDTHH:MM:SS)
            -product <product_name>         Return the CVEs that have the product name
    "#, executable_file_name);
}

/*
    Action --> Check the used options in the command line and add them in an hash map with their value (true if it has no value)
    Input --> the arguments provided on the command line as Vec<String>
              mandatory parameter to check against as &str
    Output --> return a hash map that holds the used options with it values as HashMap<String, String>
    Calls --> From helper_fucntions.rs:
                insert_specified_options(args: &[String], option: &str, options_values: &mut std::collections::HashMap<String, String>)
                get_option_value(args: &[String], option: &str) -> Option<String>
    Called In --> main.rs: Main function
*/
pub fn check_used_options(args: Vec<String>, mandatory_param: &str) -> std::collections::HashMap<String, String> {

    // Initilize the hash map we want to insert the options and the values in (this will be returned in the end)
    let mut options_values: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    // Check if the option is provided or not and insert it with the value (true) if yes
    insert_specified_options(&args, "-id", &mut options_values);
    insert_specified_options(&args, "-summary", &mut options_values);
    insert_specified_options(&args, "-cvss", &mut options_values);
    insert_specified_options(&args, "-cvss-version", &mut options_values);
    insert_specified_options(&args, "-cvss-v2", &mut options_values);
    insert_specified_options(&args, "-cvss-v3", &mut options_values);
    insert_specified_options(&args, "-epss", &mut options_values);
    insert_specified_options(&args, "-ranking-epss", &mut options_values);
    insert_specified_options(&args, "-kev", &mut options_values);
    insert_specified_options(&args, "-propose-action", &mut options_values);
    insert_specified_options(&args, "-ransomware-campaign", &mut options_values);
    insert_specified_options(&args, "-references", &mut options_values);
    insert_specified_options(&args, "-published-time", &mut options_values);
    insert_specified_options(&args, "-cpes", &mut options_values);

    // If the user wanted to use the parameter { --cves, -cs } then add the real value of the option 
    if mandatory_param == "cves" {

        // Value here is true becuase these options have no real value
        insert_specified_options(&args, "-is-kev", &mut options_values);
        insert_specified_options(&args, "-sort-by-epss", &mut options_values);

        if get_option_value(&args, "-product").is_some() {
            
            match get_option_value(&args, "-product") {
                Some(value) => options_values.insert("product".to_string(), value.to_string()),
                None => None
            };
        }

        if get_option_value(&args, "-skip").is_some() {
            
            match get_option_value(&args, "-skip") {
                Some(value) => options_values.insert("skip".to_string(), value.to_string()),
                None => None
            };
        }

        if get_option_value(&args, "-limit").is_some() {
            
            match get_option_value(&args, "-limit") {
                Some(value) => options_values.insert("limit".to_string(), value.to_string()),
                None => None
            };
        }

        if get_option_value(&args, "-start-date").is_some() {
            
            match get_option_value(&args, "-start-date") {
                Some(value) => options_values.insert("start-date".to_string(), value.to_string()),
                None => None
            };
        }

        if get_option_value(&args, "-end-date").is_some() {
            
            match get_option_value(&args, "-end-date") {
                Some(value) => options_values.insert("end-date".to_string(), value.to_string()),
                None => None
            };
        }
    }

    return options_values; 
}

/*
    Action --> Check what are the values the user want to show in the table
    Input --> the cve data we got from fetching the API as &mut CVE
              options the user specifed on the command line as HashMap<String, String>
              mandatory parameter to check for CVES and CVE ID
    Calls --> From helper_functions.rs:
                unset_if_option_missing<T>(field: &mut Option<T>, option: Option<&String>)
    Called In --> main.rs: Main function
*/
pub fn cveid_specified_options(cve_data: &mut super::cve::CVE, options: HashMap<String, String>, mandatory_param: &str) {

    /*
        Used against the CVES api after the calling if this condition does not exists and the user provided no argument to print in
        table it will return an empty table so this is just a simple check to see if none fields were specified to be printed then
        get out of the function
        THIS IS SOOOOOOOOOOOOOOOOOOOOO BAD SOLUTION!
     */
    if mandatory_param == "cves" {
        
        let options_to_check: [&str; 15] = ["id", "summary", "cvss", "cvss-version", "cvss-v2", "cvss-v3", "epss", "kev", "ranking-epss", 
                                           "epss", "cpes", "propose-action", "ransomware-campaign", "published-time", "references"];
    
        if options_to_check.iter().all(|option: &&str| !options.contains_key(*option)) {
            return;
        }
    }

    // If the user specifed a value he wants to print in the table remove all those that have not been specified
    unset_if_option_missing(&mut cve_data.cve_id, options.get("id"));
    unset_if_option_missing(&mut cve_data.summary, options.get("summary"));
    unset_if_option_missing(&mut cve_data.cvss, options.get("cvss"));
    unset_if_option_missing(&mut cve_data.cvss_version, options.get("cvss-version"));
    unset_if_option_missing(&mut cve_data.cvss_v2, options.get("cvss-v2"));
    unset_if_option_missing(&mut cve_data.cvss_v3, options.get("cvss-v3"));
    unset_if_option_missing(&mut cve_data.epss, options.get("epss"));
    unset_if_option_missing(&mut cve_data.ranking_epss, options.get("ranking-epss"));
    unset_if_option_missing(&mut cve_data.propose_action, options.get("propose-action"));
    unset_if_option_missing(&mut cve_data.ransomware_campaign, options.get("ransomware-campaign"));
    unset_if_option_missing(&mut cve_data.published_time, options.get("published-time"));

    if cve_data.kev != false && options.get("kev") == None {
        cve_data.kev = false;
    }

    if !cve_data.references.is_empty() && options.get("references") == None {
        cve_data.references.clear();
    }

    if cve_data.cpes != None && options.get("cpes") == None {
        cve_data.cpes = None;
    }
}

/*
    Action --> Build the CVES API URL witht he user specifed options 
    Input --> URL we are building as &mut String
              options we want to test it is existence and value as HashMap<String, String>
    Output --> None
    Call --> From helper_functions:
                does_not_start_with_hyphen(option_value: &str) -> bool
                is_valid_unsigned_num(option_value: &String, option_name: &str) -> bool
                is_valid_date_time(option_value: &str, option_name: &str) -> bool
    Called In --> main.rs: Main funcion
*/
pub fn build_cves_request(url: &mut String, options: HashMap<String, String>) {

    /*
        This is required to initilize the url with the parameters 
        I know this is a very fucked up way to deal with it, but it works and it is SIMPLE!
    */ 
    url.push_str("?");

    // Check the existence of an option and add it is value
    if options.get("is-kev").is_some() {
        url.push_str("&is_kev=true");
    }

    if options.get("sort-by-epss").is_some() {
        url.push_str("&sort_by_epss=true");
    }

    if let Some(skip_value) = options.get("skip") {
        
        if does_not_start_with_hyphen(&skip_value) && is_valid_unsigned_num(&skip_value, "-skip") {
            url.push_str(format!("&skip={}", skip_value).as_str());
        
        } else {
            std::process::exit(-1);
        }
    }

    if let Some(limit_value) = options.get("limit") {

        if does_not_start_with_hyphen(&limit_value) && is_valid_unsigned_num(&limit_value, "-limit") {
            url.push_str(format!("&limit={}", limit_value).as_str());
        
        } else {
            std::process::exit(-1);
        }
    }

    if let Some(product_value) = options.get("product") {

        if does_not_start_with_hyphen(&product_value) {
            url.push_str(format!("&product={}", product_value).as_str());
        
        } else {
            std::process::exit(-1);
        } 
    }

    if let Some(start_date_value) = options.get("start-date") {

        if does_not_start_with_hyphen(&start_date_value) && is_valid_date_time(&start_date_value, "start-date") {
            url.push_str(format!("&start_date={}", start_date_value).as_str());
        
        } else {
            std::process::exit(-1);
        } 
    }

    if let Some(end_date_value) = options.get("end-date") {

        if does_not_start_with_hyphen(&end_date_value) && is_valid_date_time(&end_date_value, "end-date") {
            url.push_str(format!("&end-date={}", end_date_value).as_str());
        
        } else {
            std::process::exit(-1);
        } 
    }
}

/*
    Action --> Format the table we want to print to make each row have no mor than a ceratin number of words in one line
    Input --> text we want to format as String
              max length of the line as usize
    Output --> formated string with the wanted length of words in each line as String
    Calls --> None
    Called In --> cve.rs:
                    formated_cve_table(&self)
*/
pub fn table_text_formatter(text: String, max_len: usize) -> String {
    
    let mut wrapped_text: String = String::new();
    let mut line: String = String::new();

    for word in text.split_whitespace() {
        
        if line.len() + word.len() + 1 > max_len {
            
            wrapped_text.push_str(&line);
            wrapped_text.push('\n');
            line.clear();
        }
        
        if !line.is_empty() {
            line.push(' ');
        }
        
        line.push_str(word);
    }

    wrapped_text.push_str(&line);
    
    return wrapped_text;
}

/*
    Action --> Because the reference have a weird way to be formated in the table this function will save the problem
    Input --> the references that we got from the fetched API as Vec<String>
              max length we want each reference to have as usize
    Output --> the formatted references as String
    Calls --> None
    Called In --> cve.rs:
                    formated_cve_table(&self)
*/
pub fn references_formatter(references: Vec<String>, max_len: usize) -> String {

    let fmt_references: String = references
    .iter()
    .map(|reference: &String| {
        // Split the reference into chunks of a specific character width
        reference
            .chars()
            .collect::<Vec<char>>()
            .chunks(max_len) // The width limit for each line
            .map(|chunk: &[char]| chunk.iter().collect::<String>())
            .collect::<Vec<String>>()
            .join("\n")
    }).collect::<Vec<String>>().join("\n\n");
    
    return fmt_references;
}