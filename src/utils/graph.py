import networkx as nx
import pendulum
import community as community_louvain
import numpy as np
from neo4j import GraphDatabase
from pyvis.network import Network
from typing import Dict, Any, List, Optional

from src.settings import Constants
from src.utils.logger import LoggerFactory

logger = LoggerFactory.get_logger(__name__)


class GraphBuilder:
    def __init__(
        self,
        uri: str,
        restaurants: Optional[List[Dict[str, Any]]] = None,
        username: str = "",
        password: str = "",
        build_network: bool = False,
    ):
        """
        Constructor for GraphBuilder class.

        Args:
            uri (str): URI of the Neo4j database.
            restaurants (Optional[List[Dict[str, Any]]]): A list of dictionaries containing the restaurant details.
            username (str): Username of the Neo4j database. Default is an empty string.
            password (str): Password of the Neo4j database. Default is an empty string.
            build_network (bool): A flag to build the graph network. Default is False.
        """
        try:
            self._driver = GraphDatabase.driver(
                uri=uri,
                auth=(username, password),
            )
            self._restaurants = restaurants
            self._build_network = build_network
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j database: {e}")
            raise e

    def _create_constraints(self):
        """
        Creates constraints for unique nodes.
        """
        with self._driver.session() as session:
            try:
                session.run(
                    "CREATE CONSTRAINT restaurant_url IF NOT EXISTS FOR (r:Restaurant) REQUIRE r.url IS UNIQUE"
                )
                session.run(
                    "CREATE CONSTRAINT cuisine_name IF NOT EXISTS FOR (c:Cuisine) REQUIRE c.name IS UNIQUE"
                )
                session.run(
                    "CREATE CONSTRAINT reviewer_type IF NOT EXISTS FOR (rt:ReviewerType) REQUIRE rt.type IS UNIQUE"
                )

                logger.info("Constraints created successfully!")
            except Exception as e:
                logger.error(f"Failed to create constraints: {e}")
                raise e

    def _create_restaurant(self, restaurant: Dict[str, Any]) -> None:
        """
        Creates a restaurant node in the graph.

        Args:
            restaurant (Dict[str, Any]): A dictionary containing the restaurant details.
        """
        try:
            with self._driver.session() as session:
                # Extract name from URL or use the name provided
                restaurant_name = restaurant.get(
                    "name",
                    restaurant.get("url", "").split("-")[-1]
                    if "-" in restaurant.get("url", "")
                    else "Unknown",
                )

                # Create a restaurant node
                query = """
                MERGE (r:Restaurant {url: $url})
                SET r.name = $name,
                    r.address = $address,
                    r.latitude = $lat,
                    r.longitude = $long,
                    r.price_range = $price_range,
                    r.ranking = $ranking,
                    r.rating = $rating,
                    r.review_count = $review_count
                RETURN r
                """

                session.run(
                    query=query,
                    url=restaurant.get("url", ""),
                    name=restaurant_name,
                    address=restaurant.get("address", ""),
                    lat=restaurant.get("latitude", None),
                    long=restaurant.get("longitude", None),
                    price_range=restaurant.get("price_range", ""),
                    ranking=restaurant.get("ranking", None),
                    rating=restaurant.get("rating", None),
                    review_count=restaurant.get("review_count", 0),
                )

                # Create cuisine nodes and relationships
                for cuisine in restaurant.get("cuisines", []):
                    query = """
                    MERGE (c:Cuisine {type: $cuisine})
                    WITH c
                    MATCH (r:Restaurant {url: $url})
                    MERGE (r)-[:HAS_CUISINE]->(c)
                    """

                    session.run(
                        query=query,
                        cuisine=cuisine,
                        url=restaurant.get("url", ""),
                    )

                # Create reviews
                for review in restaurant.get("reviews", []):
                    query = """
                    MATCH (r:Restaurant {url: $url})
                    MERGE (rt:ReviewerType {type: $review_type})
                    CREATE (rev:Review {
                        title: $title,
                        text: $text,
                        rating: $rating,
                        date: $review_date,
                        review_type: $review_type
                    })
                    CREATE (rev)-[:ABOUT]->(r)
                    CREATE (rev)-[:BY]->(rt)
                    """

                    session.run(
                        query=query,
                        url=restaurant.get("url", ""),
                        review_type=review.get("review_type", "Unknown"),
                        title=review.get("title", ""),
                        text=review.get("text", ""),
                        rating=review.get("rating", None),
                        review_date=review.get(
                            "review_date", pendulum.now().isoformat()
                        ),
                    )

                logger.info(f"Restaurant {restaurant_name} processed successfully!")

        except Exception as e:
            logger.error(f"Failed to create restaurant node: {e}")
            raise e

    def _create_restaurants(self) -> None:
        """
        Creates restaurant nodes in the graph.

        Args:
            restaurants (Dict[str, Any]): A dictionary containing the restaurant details.
        """
        start_time = pendulum.now()
        successfull_creation = 0
        failed_creation = 0

        for restaurant in self._restaurants:
            try:
                self._create_restaurant(restaurant)
                successfull_creation += 1
            except Exception as e:
                logger.error(f"Failed to create restaurant node: {e}")
                failed_creation += 1

        end_time = pendulum.now()
        logger.info(
            f"Processed {successfull_creation} restaurants in {end_time.diff(start_time).in_seconds()} seconds."
        )
        logger.info(f"Failed to process {failed_creation} restaurants.")

    def _build_graph(self) -> nx.Graph:
        """
        Builds the graph network by querying the Neo4j database.

        Returns:
            nx.Graph: A NetworkX graph object.
        """
        try:
            with self._driver.session() as session:
                query = """
                MATCH (r:Restaurant)-[:HAS_CUISINE]->(c:Cuisine)
                RETURN r.url AS restaurant, c.type AS cuisine
                """

                result = session.run(query=query)

                g = nx.Graph()

                for record in result:
                    g.add_node(record["restaurant"], label="Restaurant")
                    g.add_node(record["cuisine"], label="Cuisine")
                    g.add_edge(record["restaurant"], record["cuisine"])

                logger.info("Graph network built successfully!")

                return g
        except Exception as e:
            logger.error(f"Failed to build graph network: {e}")
            raise

    def build(self) -> Optional[nx.Graph]:
        """
        Builds the graph network by creating constraints and nodes.
        """
        self._create_constraints()
        self._create_restaurants()

        if self._build_network:
            return self._build_graph()
    

class GraphVisualization:
    def __init__(
        self,
        g: nx.Graph,
        partition: Dict[str, Any] = None,
        title: str = "Visualization of Graph Network",
        file_path: str = Constants.GRAPH_NETWORK_HTML_FILEPATH,
    ):
        """
        Constructor for GraphVisualization class.

        Args:
            g (nx.Graph): A NetworkX graph object.
            partition (Dict[str, Any]): A dictionary containing the community partition of the graph.
            title (str): Title of the graph network visualization.
            file_path (str): File path to save the graph network visualization.
        """
        if not isinstance(g, nx.Graph):
            raise ValueError("The input graph must be a NetworkX graph object.")
        
        self._g = g
        self._partition = partition
        self._title = title
        self._file_path = file_path

    @property
    def partition(self) -> Dict[str, Any]:
        """
        Getter for the partition property.
        """
        return self._partition
    
    @partition.setter
    def partition(self, partition: Dict[str, Any]) -> None:
        self._partition = partition

    def visualize(self) -> str:
        """
        Visualizes the graph network using the PyVis library.

        Returns:
            str: File path to the saved HTML file.
        """
        net = Network(height="800px", width="100%", notebook=True, heading=self.title)
        net.show_buttons()

        # Assign colors based on communities
        if self._partition:
            unique_communities = set(self._partition.values())
            color_map = {
                community: f"#{hash(community) % 0xFFFFFF:06x}"
                for community in unique_communities
            }
        else:
            color_map = None

        # Construct the nodes
        for node in self._g.nodes:
            # Node size based on degree
            degree = self._g.degree[node]
            net.add_node(
                node,
                label=str(node),
                color=color_map[self._partition[node]] if color_map else "#000000",
                size=degree * 2
            )

        # Construct the edges
        for edge in self._g.edges:
            net.add_edge(edge[0], edge[1])

        net.show(self._file_path)

        return self._file_path


class GraphAnalyzer:
    def __init__(self, g: nx.Graph):
        """
        Constructor for GraphAnalyzer class.

        Args:
            g (nx.Graph): A NetworkX graph object.
        """
        if not isinstance(g, nx.Graph):
            raise ValueError("The input graph must be a NetworkX graph object.")
        
        self._g = g
        self._gv = GraphVisualization(g)
        
    def _analyze_communities(self) -> Dict[str, Any]:
        """
        Analyze detected communities and provide additional insights.
        
        Returns:
            Dict[str, Any]: A dictionary containing the community insights.
        """
        communities = {}
        partition = self._gv.partition
        for community_id in set(partition.values()):
            # Nodes in this community
            community_nodes = [node for node, comm in partition.items() if comm == community_id]
            
            # Subgraph for this community
            community_subgraph = self._g.subgraph(community_nodes)
            
            communities[community_id] = {
                'num_nodes': len(community_nodes),
                'num_edges': community_subgraph.number_of_edges(),
                'avg_degree': np.mean([deg for node, deg in community_subgraph.degree()]),
                'density': nx.density(community_subgraph)
            }
        
        return communities
    
    def detect_communities(self, method: str = 'louvain') -> Dict[str, Any]:
        """
        Detects communities in the graph network using the Louvain algorithm.
        
        Args:
            method (str): The method used to detect communities. Default is 'louvain'.

        Returns:
            Dict[str, Any]: A dictionary containing the community partition of the graph.
        """
        # Community detection methods
        if method == "louvain":
            partition = community_louvain.best_partition(self._g)
        elif method == "girvan_newman":
            comp = list(nx.community.girvan_newman(self._g))
            partition = {node: idx for idx, community_set in enumerate(comp[0]) for node in community_set}
        elif method == 'label_propagation':
            partition = nx.community.label_propagation_communities(self._g)
            partition = {node: idx for idx, comm in enumerate(partition) for node in comm}
        else:
            raise ValueError(f"Invalid community detection method: {method}")
        
        # Update partition property for visualization
        self._gv.partition = partition
        
        # Plot the graph network
        self._gv.visualize()
        
        # Additional community analysis
        community_insights = self._analyze_communities()
        
        return {
            'partition': partition,
            'num_communities': len(set(partition.values())),
            'statistics': community_insights
        }