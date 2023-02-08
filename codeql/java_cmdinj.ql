import java.lang.String
import semmle.code.java.dataflow.TaintTracking

class CommandInjectionVulnerability extends TaintTracking {
  /**
   * This method checks for instances where a user input is used as a parameter in
   * executing a system command. If user input is used in this manner, the input
   * may be interpreted as a shell command, leading to command injection.
   */
  override predicate isSource(DataFlow::Node source) {
    // Identify user inputs as sources of taint
    source.getValue() instanceof StringLiteral ||
    source.getValue() instanceof UserInput ||
    source.getValue() instanceof InputStream
  }

  /**
   * This method checks for instances where user input is passed as a parameter
   * to the exec() method of the Runtime or ProcessBuilder classes.
   * These classes are used to execute system commands.
   */
  override predicate isSink(DataFlow::Node sink) {
    // Check for instances where user input is passed as a parameter to the exec() method
    sink.getMethodName().matches("exec") &&
    sink.getMethodReceiverType().matches("java.lang.Runtime|java.lang.ProcessBuilder")
  }

  /**
   * This method defines the taint propagation rule, indicating that if a source
   * is connected to a sink, a vulnerability has been detected.
   */
  override predicate isVulnerable(DataFlow::Path path) {
    isSource(path.getSourceNode()) && isSink(path.getSinkNode())
  }
}
