(fn_item body: (block ("{" (_)* @function.inside "}"))) @function.around
(extern_fn) @function.around
(label_stmt body: (block ("{" (_)* @function.inside "}"))) @function.around
(comment)+ @comment.around
