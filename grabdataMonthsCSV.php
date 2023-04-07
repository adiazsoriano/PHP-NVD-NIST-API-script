<?php
/**
 * Using the NVD NIST gov vulnerabilities API (CVE API)
 * https://nvd.nist.gov/developers/vulnerabilities
 * 
 * The purpose of this PHP script is to grab data from the NVD NIST API,
 * taking the vulnerability entries and formatting them in the CSV format.
 * The script retrieves a number entries per month for every month in a given year.
 * 
 * 
 * Argument usage ($argv):
 * $argv[0] = this filename => grabdataMonthsCSV.php
 * $argv[1] = output filename => "example.csv" or ""
 * $argv[2] = starting year (inclusive) => 1988 - 2023
 * $argv[3] = ending year (inclusive) => 1988 - 2023
 * $argv[4] = csv header filename => exampleheaders.txt
 * $argv[5] = NVD API Arguments (include & when adding) => noRejected& (any other parms)
 *                                                         more info under CVE API Parameters
 * 
 * Example(s) in CMD/Shell:
 * $ php grabdataMonthsCSV.php "somedata.csv" 1988 2023 "someCSVHeaders.txt" "noRejected&"
 * $ php grabdataMonthsCSV.php
 */


//contains apiKeyConfig
include "config.php";

//constants
define("prevLineCR","\e[f");
define("clearLine","\e[2K");
define("clearScreen","\e[2J");

/**
 * Calls the NVD API given arguments
 * With an API key, 50 calls per 30 seconds are allowed.
 * Without an API key, 5 calls per 30 seconds.
 */
function callNVDAPI(CurlHandle $ch, int $year, int $m, int $startIndex, string $args = "", bool $apiKeyExists = false) : string | bool {
    $data = false;
    $daysInMonth = cal_days_in_month(CAL_GREGORIAN,$m,$year);
    $month =  sprintf("%02d",$m);


    do {
        //https://services.nvd.nist.gov/rest/json/cves/2.0
        curl_setopt($ch, CURLOPT_URL, "https://services.nvd.nist.gov/rest/json/cves/2.0/?{$args}pubStartDate={$year}-{$month}-01T00:00:00&pubEndDate={$year}-{$month}-{$daysInMonth}T23:59:59&resultsPerPage=2000&startIndex={$startIndex}");
        curl_setopt($ch, CURLOPT_HEADER, false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        //API Key Authorization
        if($apiKeyExists) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, array(apiKeyConfig));
        }
    
        $data = curl_exec($ch);
        $info = curl_getinfo($ch);


        if($info["http_code"] === 403) { //403 is FORBIDDEN
            $curTime = time();
            while(time() <= $curTime+31) { //api specifies that a 30 second wait is needed for more calls
                $seconds = ($curTime+31) - time();
                printf("\n\nWaiting... %2d seconds left.\n%s",$seconds,prevLineCR);
                sleep(1);
            } 
            printf("\n\n%s",clearLine.prevLineCR); //clear "waiting..."
        }
    
    } while($info["http_code"] !== 200); //200 is OK

    return $data;
}

/**
 * Writes a given entry to a given file
 * The format is in CSV
 */
function writeEntryToFile(array $entry, mixed $file, array $headers, int &$rowCount) : void {

    foreach($entry["vulnerabilities"] as $vuln) {
        $row = "";
        foreach($headers as $header) {
            if($header == null || (is_array($header) && $header[0] == null)) { //depedent if read from file or initialized here.
                $row .= $rowCount . ",";
                $rowCount++;
            } else {
                $element = fetch_in_array($vuln,$header);
                if($element) {
                    $row .= is_numeric($element) ? $element : "\"{$element}\"";
                }//if not true, it's an empty cell  
                $row .= ",";
            }
        } 
        $row = substr($row,0,strlen($row) - 1);
        fwrite($file,$row.PHP_EOL);
    }
}

/**
 * fetches an item given an array and arguments
 */
function fetch_in_array(array $array, array $args) : mixed {
    $item = $array;
    foreach($args as $arg) {
        if(!isset($item[$arg])) {
            return null;
        }
        $item = $item[$arg];
    }
    return $item;
}

/**
 * Reads in a file and turns it into header and associative array data
 * 
 * In file format (.txt):
 * [HEADER]:[DATA],[DATA],...,[DATA]
 * 
 * Example:
 * sourceIdentifier:cve,sourceIdentifier
 */
function readInCSVHeader(string $filename) : array {
    $filestream = fopen($filename,"r");
    $header = array();

    do {
        $line = fgets($filestream);
        if($line !== false) {
            $sepHeaderFromData = explode(":",trim($line));

            $header[$sepHeaderFromData[0]] = convertTypesInArray(explode(",",$sepHeaderFromData[1]));
        }
    } while($line !== false);

    fclose($filestream);
    return $header;
}

/**
 * Parses items in array and converts them to appropriate type
 */
function convertTypesInArray(array $items) : array | null {
    $convertedItems = array();

    foreach($items as $item) {
        $newItem = $item;
        if(preg_match("/^[0-9]+$/", $item)) {
            $newItem = intval($item);
        } elseif($item == "null") {
            $newItem = null;
        }

        array_push($convertedItems,$newItem);
    }

    return $convertedItems;
}

/**
 * Prints a status given current status and total
 */
function printStatus(int $status, int $total) : void {
    $current = ($status / ($total-1)) * 100.0;
    $progressBarFill = str_repeat("#",intval($current / 4));
    $progressBarEmpty = str_repeat(".", (25 - intval($current / 4)));
    printf("Status: [%s%s] %.02f%%\n%s",$progressBarFill,$progressBarEmpty,$current,prevLineCR);
}


/**
 * Prints the status of year & month
 */
function printYearMonthStatus(int $year, int $month) :void {
    printf("Completing %2d, %5d\n",$month,$year);
}

/**
 * Checks if specified command-line arguments are valid.
 * If invalid, exits program.
 */
function checkValidArgs(array $argv) : void {
    $validArgs = true;

    //check for valid year range
    if(isset($argv[2]) && isset($argv[3]) && 
       ((!preg_match("/^[0-9]+$/", $argv[2]) &&
       !preg_match("/^[0-9]+$/", $argv[3])) ||
       $argv[2] > $argv[3])) {
        echo "Please enter the proper input for year.\n";
        echo "year1 must be less than or equal to year2.\n";
        echo "- - - - - - - - - - - - - - - - - - - - - - - - -\n";
        
        $validArgs = false;
    }

    //check for valid csvHeaders file
    if(isset($argv[4]) && !empty($argv[4] && !file_exists($argv[4]))) {
        echo "Please enter a csv header txt file that exists.\n";
        echo "- - - - - - - - - - - - - - - - - - - - - - - - -\n";
        
        $validArgs = false;
    }

    if(!$validArgs) {
        gracefullyExit();
    }
}

/**
 * Exits given a file and a curl handle, closing them and exiting.
 * If nothing is provided, then closes gracefully.
 */
function gracefullyExit(mixed $file = null, CurlHandle $ch = null) : void {
    if($file != null) {
        fclose($file);
    }
    if($ch != null) {
        curl_close($ch);
    }
    exit(0);
}

//checks if args are valid, exits if not valid                                   
checkValidArgs($argv);

//ApiKey Check
$apiKeyExists = false;
try {
    if(apiKeyConfig !== null) {
        $apiKeyExists = true;
    } 
} catch(Error $e) {}

//init variables
$rowCount = 1;
$monthStatus = 0;

$ch = curl_init();
$data;

$file = fopen(isset($argv[1]) && 
             !empty($argv[1]) ? $argv[1] : "vulnData.csv","w");
$yearRange = array(isset($argv[2]) ? intval($argv[2]) : 1988,
                   isset($argv[3]) ? intval($argv[3]) : 2023);
$totalMonths = (abs($yearRange[1] - $yearRange[0]) + 1) * 12;
$csvHeaders = isset($argv[4]) && 
              !empty($argv[4]) ? readInCSVHeader($argv[4]) : 
                                array("row#" => null,
                                "id" => array("cve","id"),
                                "sourceIdentifier" => array("cve","sourceIdentifier"),
                                "published" => array("cve", "published"),
                                "lastModified" => array("cve", "lastModified"),
                                "vulnStatus" => array("cve", "vulnStatus"),
                                "attackVector_V31" => array("cve","metrics", "cvssMetricV31", 0, "cvssData", "attackVector"),
                                "cvssMetricV31_baseScore" => array("cve", "metrics", "cvssMetricV31", 0, "cvssData", "baseScore"),
                                "cvssMetricV31_baseSeverity" => array("cve", "metrics", "cvssMetricV31", 0, "cvssData", "baseSeverity"),
                                "cvssMetricV2_baseScore" => array("cve", "metrics", "cvssMetricV2", 0, "cvssData", "baseScore"),
                                "cvssMetricV2_baseSeverity" => array("cve", "metrics", "cvssMetricV2", 0, "baseSeverity"),
                                "accessVector_V2" => array("cve", "metrics", "cvssMetricV2", 0, "cvssData", "accessVector"));


//write header to csv
$dataheader = "";
foreach($csvHeaders as $key => $value) {
    $dataheader .= $key . ",";
}
$dataheader = rtrim($dataheader,",");
fwrite($file,$dataheader.PHP_EOL);
unset($dataheader);

//setup terminal output
printf("%s",clearScreen.prevLineCR);

//gather data & format to CSV
for($i = $yearRange[0]; $i <= $yearRange[1]; $i++) {
    for($j = 1; $j < 13; $j++) {
        $startIndex = 0;
        $data;

        printYearMonthStatus($i,$j);
        printStatus($monthStatus,$totalMonths);
        do {
            $data = json_decode(callNVDAPI($ch,$i,$j,$startIndex, isset($argv[5]) ? $argv[5] : "",$apiKeyExists), true);
            try {
                writeEntryToFile($data, $file, $csvHeaders, $rowCount);
            } catch (TypeError $te) {
                echo "\n\n\n\n TypeError was thrown for file writing, aborting.\n";
                gracefullyExit($file,$ch);
            }
            //each response gives 2000 entries
            $startIndex += 2_000;
        } while($startIndex < $data["totalResults"]);

        $monthStatus++;
    }
}

echo PHP_EOL.PHP_EOL.PHP_EOL;



//closing streams/handles
curl_close($ch);
fclose($file);

?>