/*
    Contains the CVE structure that represent the data fetched from the Shodan API  
*/

use cli_table::{format::Justify, Cell, CellStruct, Style, Table, TableStruct};

/*
    Structure represnet the CVE ID data fetched from the Shoadan API
*/
#[derive(serde::Deserialize, Debug)]
pub struct CVE {

    pub cve_id: Option<String>,
    pub summary: Option<String>,
    pub cvss: Option<f32>,
    pub cvss_version: Option<f32>,
    pub cvss_v2: Option<f32>,
    pub cvss_v3: Option<f32>,
    pub epss: Option<f32>,
    pub ranking_epss: Option<f32>,
    pub kev: bool,
    pub propose_action: Option<String>,
    pub ransomware_campaign: Option<String>,
    pub references: Vec<String>,
    pub published_time: Option<String>,
    pub cpes: Option<Vec<String>>
}

/*
     Structure represne the CVEs data fetched from the Shoadan API
*/
#[derive(serde::Deserialize, Debug)]
pub struct CVES {
    pub cves: Vec<CVE>
}

/*
    CVE Functions
*/
impl CVE {

    /*
        Initlize a new CVE structure
    */
    pub fn new() -> Self {
        
        CVE {
            cve_id: None,
            summary: None,
            cvss: None,
            cvss_version: None,
            cvss_v2: None,
            cvss_v3: None,
            epss: None,
            ranking_epss: None,
            kev: false,
            propose_action: None,
            ransomware_campaign: None,
            references: Vec::new(),
            published_time: None,
            cpes: None,
        }
    }

    /*
        Action --> Print the formated table for the CVE data using the cli_table library
        Input --> CVE we want to print as &self
        Output --> None
        Calls --> From helper_functions.rs:
                    table_text_formatter(text: String, max_len: usize): to format the string to fit in the table
                    references_formatter(references: Vec<String>, max_len: usize): to format the refrenses to fit in the table
                    ^ I know this is shit implementation but this is what I got!
        Called In: main.rs: Main function
     */
    pub fn formated_cve_table(&self) {

        // The table we will print in the end
        let mut table_rows: Vec<Vec<CellStruct>> = Vec::new();

        if self.cve_id != None {
            table_rows.push(vec![
                "CVE ID".cell(), self.cve_id.as_ref().unwrap().cell().justify(Justify::Center)
            ]);
        }

        if self.summary != None {
            table_rows.push(vec![
                "Summary".cell(), 
                super::helper_functions::table_text_formatter(self.summary.as_ref().unwrap().to_string(), 55).cell().justify(Justify::Center)
            ]);
        }

        if self.cvss != None {
            table_rows.push(vec![
                "CVSS".cell(),
                self.cvss.unwrap().cell().justify(Justify::Center)
            ]);
        }

        if self.cvss_version != None {
            table_rows.push(vec![
                "CVSS Version".cell(),
                self.cvss_version.unwrap().cell().justify(Justify::Center)
            ]);
        }

        if self.cvss_v2 != None {
            table_rows.push(vec![
                "CVSS V2".cell(),
                self.cvss_v2.unwrap().cell().justify(Justify::Center)
            ]);
        }

        if self.cvss_v3 != None {
            table_rows.push(vec![
                "CVSS V3".cell(),
                self.cvss_v3.unwrap().cell().justify(Justify::Center)
            ]);
        }

        if self.epss != None {
            table_rows.push(vec![
                "EPSS".cell(),
                self.epss.unwrap().cell().justify(Justify::Center)
            ]);
        }

        if self.ranking_epss != None {
            table_rows.push(vec![
                "Ranking EPSS".cell(),
                self.ranking_epss.unwrap().cell().justify(Justify::Center)
            ]);
        }

        if self.kev == true {
            table_rows.push(vec![
                "KEV".cell(),
                self.kev.cell().justify(Justify::Center)
            ]);
        }

        if self.propose_action != None {
            table_rows.push(vec![
                "Propose Action".cell(),
                super::helper_functions::table_text_formatter(
                    self.propose_action.as_ref().unwrap().clone(), 55).cell().justify(Justify::Center)
            ]);
        }

        if self.ransomware_campaign != None {
            table_rows.push(vec![
                "Ransomware Campaign".cell(),
                super::helper_functions::table_text_formatter(
                    self.ransomware_campaign.as_ref().unwrap().clone(), 55).cell().justify(Justify::Center)
            ]);
        }

        if !self.references.is_empty() {
            table_rows.push(vec![
                "References".cell(),
                super::helper_functions::references_formatter(self.references.clone(), 55).cell().justify(Justify::Center)
            ]);
        }

        if self.published_time != None  {
            table_rows.push(vec![
                "Published Time".cell(),
                self.published_time.as_ref().unwrap().cell().justify(Justify::Center)
            ]);
        }

        if self.cpes != None {
            table_rows.push(vec![
                "CPES".cell(),
                super::helper_functions::table_text_formatter(self.cpes.clone().unwrap().join("\t"), 55).cell().justify(Justify::Center)
            ]);
        }

        let table: TableStruct = table_rows.table().title(vec![
            
            "Name".cell().bold(true).justify(Justify::Center),
            "Description".cell().bold(true).justify(Justify::Center),
        
        ]).bold(true);

        println!("\n{}", table.display().unwrap());
    }
}

