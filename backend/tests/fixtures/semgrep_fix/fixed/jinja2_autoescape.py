import jinja2

ENV = jinja2.Environment(
    loader=jinja2.FileSystemLoader("templates"),
    autoescape=True,
    trim_blocks=True,
)
