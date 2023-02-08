import java

class XXE extends Method {
  XXE() {
    super.name = "parse" and
      super.declaringType.name = "javax.xml.parsers.DocumentBuilder" and
      super.parameterCount = 1 and
      super.getParameter(0).type.name = "java.io.InputStream";
  }

  override predicate isViolation() {
    for (MethodCall call : getMethodCallsTo(this)) {
      // Check if the parse method is called with a DocumentBuilder that is not secure
      if (!call.getThis().toMethod().hasAnnotation("javax.xml.parsers.DocumentBuilderFactory", "setFeature")) {
        return true;
      }
    }
    return false;
  }
}

query XXE {
  // Find all XXE vulnerabilities
  XXE().isViolation()
}
