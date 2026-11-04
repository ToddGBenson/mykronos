import jinja2

ENV = jinja2.Environment(
    loader=jinja2.FileSystemLoader("templates"),
    autoescape=False,
    trim_blocks=True,
)
