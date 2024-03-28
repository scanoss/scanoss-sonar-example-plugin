package com.scanoss.plugins.sonar.analyzers;

import com.scanoss.dto.ScanFileDetails;
import com.scanoss.dto.ScanFileResult;
import com.scanoss.plugins.sonar.model.ScanResult;
import com.scanoss.plugins.sonar.utils.PackageDetails;
import com.scanoss.utils.JsonUtils;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;

import java.io.File;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * SCANOSS Analyzer
 *
 * <p>
 * Performs a scan and processes the output
 * </p>
 */
public class ScanOSSAnalyzer {

    /**
     * The project root directory.
     */
    private final File rootDir;

    /**
     * The API  URL.
     */
    private final String url;

    /**
     * The API key/token
     */
    private final String key;

    /**
     * The Custom Certificate Chain
     */
    private final String customCertChain;

    /**
     * The logger.
     */
    private final Logger log = Loggers.get(this.getClass());

    /**
     * SBOM identify file name
     */
    private final String sbomIdentify;


    /**
     * SBOM identify file name
     */
    private final String sbomIgnore;

    /**
     * Analyzer constructor
     *
     * @param rootDir         Base directory to scan
     * @param url             SCANOSS API Endpoint
     * @param key             SCANOSS API Access Key (optional)
     * @param customCertChain SCANOSS Custom Certificate Chain (optional)
     */
    public ScanOSSAnalyzer(final File rootDir, String url, String key, String customCertChain, String sbomIdentify, String sbomIgnore) {
        super();
        this.rootDir = rootDir;
        this.url = url;
        this.key = key;
        this.customCertChain = customCertChain;
        this.sbomIdentify = sbomIdentify;
        this.sbomIgnore = sbomIgnore;
    }

    /**
     * This function calls the SCANOSS scanner for a given set of file paths and processes the output
     * @param inputFilePaths List of input file paths
     * @return Scan result with a map containing all filenames as keys and the scan results as values
     */
    public ScanResult analyze(List<String> inputFilePaths)  {
        log.info("[SCANOSS] Starting scan process...");
        log.info("[SCANOSS] Plugin version: {} (SDK version: {})", PackageDetails.getVersion(), com.scanoss.utils.PackageDetails.getVersion());
        log.info("[SCANOSS] Root path " + this.rootDir.getPath());
        ScanOSSScanner scanner = new ScanOSSScanner(this.url, this.key, this.customCertChain, this.sbomIdentify, this.sbomIgnore, this.rootDir);
        List<String> output = scanner.runScan(rootDir.getPath(), inputFilePaths);
        if(output == null || output.isEmpty()){
            log.warn("[SCANOSS] Empty result");
            return new ScanResult();
        }
        // Process output
        return processOutput(output);
    }

    private ScanResult processOutput(List<String> output){
        ScanResult scanResult = new ScanResult();
        List<ScanFileResult> outputObject = JsonUtils.toScanFileResults(output);
        Map<String, List<ScanFileDetails>> map = outputObject.stream().collect(Collectors.toMap(ScanFileResult::getFilePath, ScanFileResult::getFileDetails));
        scanResult.setFiles(map);
        return scanResult;
    }

}
