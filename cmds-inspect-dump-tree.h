int cmd_inspect_dump_tree(int ac, char **av);


static const char * const cmd_inspect_dump_tree_usage[] = {
	"btrfs inspect-internal dump-tree [options] device",
	"Dump structures from a device",
	"-e|--extents           print detailed extents info",
	"-d|--device            print info of btrfs device and root tree dir only",
	"-r|--roots             print info of roots only",
	"-R|--backups           print info of roots and root backups",
	"-u|--uuid              print info of uuid tree only",
	"-b|--block <block_num> print info of the specified block only",
	"-t|--tree  <tree_id>   print only the tree with the given id",
	NULL
};
