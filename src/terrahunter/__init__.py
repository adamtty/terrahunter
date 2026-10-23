"""terrahunter: point it at your Terraform, and it maps the infrastructure as a diagram and walks you through the
paths an attacker could chain through it.

The pipeline, one stage per module as they're rebuilt:
  1. the folder in: find the Terraform roots in it
  2. what's missing: modules, remote state and other repositories the analysis needs, fetched or pointed at first
  3. the connections between resources, drawn as an architecture diagram (2D and 3D)
  4. vulnerability hunting: trivy and checkov findings on each resource
  5. attack paths: Internet → a resource at the edge → the interior, and whether an attacker could chain them
  6. the results: the diagram with a walkthrough of each path, plus reports
"""

__version__ = "0.1.0.dev0"
