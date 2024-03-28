  package com.scanoss.plugins.sonar.settings;

  import org.sonar.api.PropertyType;
  import org.sonar.api.config.PropertyDefinition;
  import org.sonar.api.resources.Qualifiers;

  import java.util.List;

  import static java.util.Arrays.asList;

  /**
   * SCANOSS Properties class
   */
  public class ScanOSSProperties {

  /**
   * SCANOSS API URL Configuration key
   */
  public static final String SCANOSS_API_URL_KEY = "sonar.scanoss.scan.apiurl";

  /**
   * SCANOSS API URL Configuration default value
   */
  public static final String SCANOSS_API_URL_DEFAULT_VALUE = "https://osskb.org/api/scan/direct";

  /**
   * SCANOSS API Token Configuration key
   */
  public static final String SCANOSS_API_TOKEN_KEY = "sonar.scanoss.scan.key";

  /**
   * SCANOSS API Token Configuration default value
   */
  public static final String SCANOSS_API_TOKEN_DEFAULT_VALUE = "";

  /**
   * SCANOSS Custom Certificate Chain key
   */
  public static final String SCANOSS_CUSTOM_CERT_CHAIN_KEY = "sonar.scanoss.scan.custom_cert_chain";

  /**
   * SCANOSS Custom Certificate Chain default value
   */
  public static final String SCANOSS_CUSTOM_CERT_CHAIN_DEFAULT_VALUE = "";

  /**
   * SCANOSS Enable/Disable Scan key
   */
  public static final String SCANOSS_IS_ENABLED_KEY = "sonar.scanoss.scan.enabled";


  /**
   * SCANOSS Identify
   */
  public static final String SCANOSS_SBOM_IDENTIFY = "sonar.scanoss.scan.sbom_identify";

  /**
   * SCANOSS Identify default value
   */
  public static final String SCANOSS_SBOM_IDENTIFY_DEFAULT_VALUE = "";

  /**
   * SCANOSS Ignore
   * */
  public static final String SCANOSS_SBOM_IGNORE = "sonar.scanoss.scan.sbom_ignore";

  /**
   * SCANOSS Ignore default value
   */
  public static final String SCANOSS_SBOM_IGNORE_DEFAULT_VALUE = "";


  /**
   * Private constructor to allow only statics
   */
  private ScanOSSProperties() {
    // only statics
  }

  /**
   * Builds the list of property definitions for Sonar
   * @return List of property definitions
   */
  public static List<PropertyDefinition> getProperties() {
        PropertyDefinition isEnabled = PropertyDefinition.builder(SCANOSS_IS_ENABLED_KEY)
            .multiValues(false)
            .type(PropertyType.BOOLEAN)
            .defaultValue(String.valueOf(false))
            .category("SCANOSS")
            .name("is Scan Enabled")
            .description("Is Scan OSS scaning enblaed?")
            .onQualifiers(Qualifiers.PROJECT)
            .index(0)
            .build();
    PropertyDefinition apiUrl = PropertyDefinition.builder(SCANOSS_API_URL_KEY)
            .multiValues(false)
            .defaultValue(SCANOSS_API_URL_DEFAULT_VALUE)
            .category("SCANOSS")
            .name("Scan API URL")
            .description("Scan API Endpoint with format \"http(s)://host:ip/api/scan/direct\". The --apiurl argument is used to pass it to the CLI.")
            .onQualifiers(Qualifiers.PROJECT)
            .index(1)
            .build();
    PropertyDefinition apiToken = PropertyDefinition.builder(SCANOSS_API_TOKEN_KEY)
            .multiValues(false)
            .defaultValue(SCANOSS_API_TOKEN_DEFAULT_VALUE)
            .category("SCANOSS")
            .name("Scan API Token")
            .description("Scan API token. The --key argument is used to pass it to the CLI.")
            .onQualifiers(Qualifiers.PROJECT)
            .index(2)
            .build();
    PropertyDefinition customCertChain = PropertyDefinition.builder(SCANOSS_CUSTOM_CERT_CHAIN_KEY)
            .type(PropertyType.TEXT)
            .multiValues(false)
            .defaultValue(SCANOSS_CUSTOM_CERT_CHAIN_DEFAULT_VALUE)
            .category("SCANOSS")
            .name("Custom Certificate Chain")
            .description("The custom certificate chain pem value.")
            .onQualifiers(Qualifiers.PROJECT)
            .index(3)
            .build();
    PropertyDefinition sbomIdentify = PropertyDefinition.builder(SCANOSS_SBOM_IDENTIFY)
            .multiValues(false)
            .defaultValue(SCANOSS_SBOM_IDENTIFY_DEFAULT_VALUE)
            .category("SCANOSS")
            .name("SCANOSS SBOM IDENTIFY")
            .description("SCANOSS SBOM identify filename")
            .onQualifiers(Qualifiers.PROJECT)
            .index(4)
            .build();
    PropertyDefinition sbomIgnore = PropertyDefinition.builder(SCANOSS_SBOM_IGNORE)
            .multiValues(false)
            .defaultValue(SCANOSS_SBOM_IGNORE_DEFAULT_VALUE)
            .category("SCANOSS")
            .name("SCANOSS SBOM IGNORE")
            .description("SCANOSS SBOM ignore filename")
            .onQualifiers(Qualifiers.PROJECT)
            .index(5)
            .build();

    return asList(
            isEnabled,
            apiUrl,
            apiToken,
            customCertChain,
            sbomIdentify,
            sbomIgnore
    );
  }

}
