mod "aws_alb_access_log" {
  # hub metadata
  title         = "AWS ALB Access Log Detections"
  description   = "Search your AWS ALB access logs for high risk actions using Tailpipe."
  color         = "#FF9900"
  documentation = file("./docs/index.md")
  icon          = "/images/mods/turbot/aws-alb-access-log.svg"
  categories    = ["aws", "dashboard", "detections", "public cloud"]
  database      = var.database

  opengraph {
    title       = "Tailpipe Mod for AWS ALB Access Log Detections"
    description = "Search your AWS ALB access logs for high risk actions using Tailpipe."
    image       = "/images/mods/turbot/aws-alb-access-log-social-graphic.png"
  }
} 