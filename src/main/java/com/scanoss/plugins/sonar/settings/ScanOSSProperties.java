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
  public static final String SCANOSS_API_URL_DEFAULT_VALUE = "https://api.osskb.org/scan/direct";

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
            .name("Enable SCANOSS")
            .description("Enable or disable SCANOSS plugin")
            .onQualifiers(Qualifiers.PROJECT)
            .index(0)
            .build();
    PropertyDefinition apiUrl = PropertyDefinition.builder(SCANOSS_API_URL_KEY)
            .multiValues(false)
            .defaultValue(SCANOSS_API_URL_DEFAULT_VALUE)
            .category("SCANOSS")
            .name("Scan API URL")
            .description("Scan API Endpoint with format \"http(s)://host:ip/scan/direct\". The --apiurl argument is used to pass it to the CLI.")
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

    return asList(
            isEnabled,
            apiUrl,
            apiToken,
            customCertChain
    );
  }

}
