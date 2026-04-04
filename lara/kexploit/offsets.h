//
//  offsets.h
//  lara
//
//  Created by ruter on 04.04.26.
//

#ifndef offsets_h
#define offsets_h

#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

bool dlkerncache(void);
uint64_t getkernproc(void);
uint64_t getrootvnode(void);
uint64_t getprocsize(void);
bool haskernproc(void);
NSString *getkerncache(void);
void clearkerncachedata(void);

#ifdef __cplusplus
}
#endif

#endif /* offsets_h */
