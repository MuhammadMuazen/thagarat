/*
    Contains the fetch functions used to get the shodan API data
*/

/*
    Action --> Call the API for a single CVE to fetch it
    Input --> url for the CVE API as &str
    Output --> esult<super::cve::CVE, reqwest::Error> where CVE is defined in cve.rs
    Calls --> None
    Called In --> main.rs: Main fucntion
*/
pub async fn fetch_cveid_data(url: &str) -> Result<super::cve::CVE, reqwest::Error> {
    let response: super::cve::CVE = reqwest::get(url).await?.json::<super::cve::CVE>().await?;
    Ok(response)
}

/*
    Action --> Call the API for CVES to fetch them
    Input --> url for the CVES API as &str
    Output --> Result<Vec<super::cve::CVE>, reqwest::Error> where CVE is defined in cve.rs
    Calls --> None
    Called In --> main.rs: Main function 
*/
pub async fn fetch_cves_data(url: &str) -> Result<Vec<super::cve::CVE>, reqwest::Error> {
    let response: reqwest::Response = reqwest::get(url).await?;
    let cve_response: super::cve::CVES = response.json().await?;
    Ok(cve_response.cves)
}

/*
    Why is this a seperate file? Why is it not in the cve.rs file as it should????
    Pffff I don't know! Deal with it!
*/