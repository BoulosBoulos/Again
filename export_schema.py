from sqlalchemy import create_engine, MetaData
from sqlalchemy_schemadisplay import create_schema_graph

# Connect to the same DB as the Docker services (port 5432 mapped to host)
engine = create_engine(
    "postgresql+psycopg2://smart_user:smart_password@localhost:5432/smart_meeting"
)

metadata = MetaData()
metadata.reflect(bind=engine)

graph = create_schema_graph(
    engine=engine,
    metadata=metadata,
    show_datatypes=True,
    show_indexes=True
)

output_file = "db_schema.png"
graph.write_png(output_file)
print(f"Schema diagram saved as {output_file}")
