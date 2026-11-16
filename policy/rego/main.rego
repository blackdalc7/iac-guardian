# Entrypoint compiled to WebAssembly. The Node agent only ever asks one
# question: "which violations does this document still have?"
package guardian

import data.guardian.kubernetes
import data.guardian.terraform

deny contains v if some v in terraform.violations

deny contains v if some v in kubernetes.violations
