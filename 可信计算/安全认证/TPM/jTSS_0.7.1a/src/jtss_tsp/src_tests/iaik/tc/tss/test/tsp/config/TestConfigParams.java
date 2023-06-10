package iaik.tc.tss.test.tsp.config;

import iaik.tc.utils.cmdline.Param;

public class TestConfigParams {

    public static final String PARAM_OWNER_SECRET = "-o";

    public static final String PARAM_SRK_SECRET = "-s";

    public static final String PARAM_STRING_ENCODING = "-e";

    public static final String PARAM_APPEND_NULLTERM = "-n";

    public static final String PARAM_CONFIG_FILE = "-f";

    public static Param getOwnerSecretParam()
    {
      return new Param(PARAM_OWNER_SECRET, "ownerSecret", Param.OPT_BOTH, "TPM owner password");
    }

    public static Param getSrkSecretParam()
    {
      return new Param(PARAM_SRK_SECRET, "srkSecret", Param.OPT_BOTH, "SRK password");
    }

    public static Param getEncodingParam()
    {
      return new Param(PARAM_STRING_ENCODING, "encoding", Param.OPT_BOTH, "encoding for password strings", "UTF-16LE", new String[] { "ASCII", "UTF-16", "UTF-16BE", "UTF-16LE" });
    }

    public static Param getNullTermParam()
    {
      return new Param(PARAM_APPEND_NULLTERM, "", Param.OPT_KEY, "append null termination to password strings");
    }

    public static Param getConfigFileParam()
    {
    	return new Param(PARAM_CONFIG_FILE, "test.cfg", Param.OPT_BOTH, "the config file specifying the testclasses to be run");
    }


}
