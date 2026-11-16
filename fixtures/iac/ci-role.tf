# Role assumed by the CI runners

data "aws_iam_policy_document" "ci" {
  statement {
    sid       = "Deploy"
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "ci" {
  name   = "ci-deploy"
  policy = data.aws_iam_policy_document.ci.json
}
