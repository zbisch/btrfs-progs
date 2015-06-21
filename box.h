#ifndef __BTRFS_BOX_H__
#define __BTRFS_BOX_H__

#ifdef ENABLE_BOX
#define BOX_MAIN(standalone)	standalone##_main
#else
#define BOX_MAIN(standalone)	main
#endif

int btrfstune_main(int argc, char **argv);
int mkfs_main(int argc, char **argv);
int image_main(int argc, char **argv);
int convert_main(int argc, char **argv);
int debug_tree_main(int argc, char **argv);
int find_root_main(int argc, char **argv);
int show_super_main(int argc, char **argv);

#endif
