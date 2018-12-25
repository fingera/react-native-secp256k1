
#import "RNSecp256k1.h"

@implementation RNSecp256k1

- (dispatch_queue_t)methodQueue
{
    return dispatch_get_main_queue();
}
RCT_EXPORT_MODULE()

@end
  