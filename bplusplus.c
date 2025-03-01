/**
 * B++ Compiler
 * 
 * A high-performance, production-ready compiler for the B++ programming language
 * Currently being worked on! 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <ctype.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <setjmp.h>
#include <stdarg.h>
#include <pthread.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <sys/mman.h>
#include <dlfcn.h>
#endif

/*******************************************************************************
 * Core Data Structures
 ******************************************************************************/

/* Source location tracking */
typedef struct {
    const char* filename;
    int line;
    int column;
    size_t offset;
} SourceLocation;

/* String representation with length */
typedef struct {
    char* data;
    size_t length;
    bool owned;  // Whether this string owns its data
} StringView;

/* Memory arena for efficient allocations */
typedef struct {
    char* buffer;
    size_t capacity;
    size_t used;
    struct Arena* next;
} Arena;

/* Hash table for symbol tables, string interning, etc. */
typedef struct {
    size_t capacity;
    size_t size;
    float load_factor;
    void** keys;
    void** values;
    bool* occupied;
} HashMap;

/* Dynamic array */
typedef struct {
    void* data;
    size_t element_size;
    size_t capacity;
    size_t length;
} Array;

/* Token types */
typedef enum {
    TOKEN_EOF = 0,
    
    // Keywords
    TOKEN_AUTO,
    TOKEN_BREAK,
    TOKEN_CASE,
    TOKEN_CONST,
    TOKEN_CONTINUE,
    TOKEN_DEFAULT,
    TOKEN_DO,
    TOKEN_ELSE,
    TOKEN_ENUM,
    TOKEN_EXTERN,
    TOKEN_FN,
    TOKEN_FOR,
    TOKEN_IF,
    TOKEN_IMPORT,
    TOKEN_LET,
    TOKEN_MATCH,
    TOKEN_MUT,
    TOKEN_RETURN,
    TOKEN_STRUCT,
    TOKEN_SWITCH,
    TOKEN_TYPE,
    TOKEN_USE,
    TOKEN_VAR,
    TOKEN_VOID,
    TOKEN_WHILE,
    
    // Literals
    TOKEN_IDENTIFIER,
    TOKEN_INTEGER,
    TOKEN_FLOAT,
    TOKEN_STRING,
    TOKEN_CHAR,
    TOKEN_BOOL,
    
    // Operators
    TOKEN_PLUS,            // +
    TOKEN_MINUS,           // -
    TOKEN_STAR,            // *
    TOKEN_SLASH,           // /
    TOKEN_PERCENT,         // %
    TOKEN_CARET,           // ^
    TOKEN_AMPERSAND,       // &
    TOKEN_PIPE,            // |
    TOKEN_TILDE,           // ~
    TOKEN_EXCLAMATION,     // !
    TOKEN_QUESTION,        // ?
    TOKEN_COLON,           // :
    TOKEN_SEMICOLON,       // ;
    TOKEN_COMMA,           // ,
    TOKEN_DOT,             // .
    TOKEN_EQUALS,          // =
    TOKEN_LESS_THAN,       // <
    TOKEN_GREATER_THAN,    // >
    TOKEN_LEFT_PAREN,      // (
    TOKEN_RIGHT_PAREN,     // )
    TOKEN_LEFT_BRACE,      // {
    TOKEN_RIGHT_BRACE,     // }
    TOKEN_LEFT_BRACKET,    // [
    TOKEN_RIGHT_BRACKET,   // ]
    TOKEN_HASH,            // #
    TOKEN_AT,              // @
    TOKEN_DOLLAR,          // $
    TOKEN_BACKSLASH,       // \
    
    // Compound operators
    TOKEN_PLUS_PLUS,       // ++
    TOKEN_MINUS_MINUS,     // --
    TOKEN_PLUS_EQUALS,     // +=
    TOKEN_MINUS_EQUALS,    // -=
    TOKEN_STAR_EQUALS,     // *=
    TOKEN_SLASH_EQUALS,    // /=
    TOKEN_PERCENT_EQUALS,  // %=
    TOKEN_AMPERSAND_EQUALS,// &=
    TOKEN_PIPE_EQUALS,     // |=
    TOKEN_CARET_EQUALS,    // ^=
    TOKEN_EQUALS_EQUALS,   // ==
    TOKEN_EXCLAMATION_EQUALS, // !=
    TOKEN_LESS_EQUALS,     // <=
    TOKEN_GREATER_EQUALS,  // >=
    TOKEN_AMPERSAND_AMPERSAND, // &&
    TOKEN_PIPE_PIPE,       // ||
    TOKEN_LEFT_SHIFT,      // <<
    TOKEN_RIGHT_SHIFT,     // >>
    TOKEN_LEFT_SHIFT_EQUALS, // <<=
    TOKEN_RIGHT_SHIFT_EQUALS, // >>=
    TOKEN_ARROW,           // ->
    TOKEN_FAT_ARROW,       // =>
    TOKEN_DOUBLE_COLON,    // ::
    TOKEN_TRIPLE_DOT,      // ...
    TOKEN_DOUBLE_STAR,     // **
    
    // Preprocessor
    TOKEN_PREPROCESSOR,
    
    // Special
    TOKEN_ERROR,
    TOKEN_COMMENT,
    TOKEN_WHITESPACE,
    
    TOKEN_COUNT
} TokenType;

/* Token representation */
typedef struct {
    TokenType type;
    StringView lexeme;
    SourceLocation location;
    
    union {
        int64_t int_value;
        double float_value;
        bool bool_value;
        StringView string_value;
        char char_value;
    } value;
} Token;

/* AST node types */
typedef enum {
    // Top-level declarations
    NODE_PROGRAM,
    NODE_FUNCTION_DECLARATION,
    NODE_STRUCT_DECLARATION,
    NODE_ENUM_DECLARATION,
    NODE_TYPE_ALIAS,
    NODE_IMPORT_DECLARATION,
    NODE_USE_DECLARATION,
    NODE_CONST_DECLARATION,
    NODE_STATIC_DECLARATION,
    NODE_MODULE_DECLARATION,
    
    // Statements
    NODE_BLOCK,
    NODE_EXPRESSION_STATEMENT,
    NODE_VARIABLE_DECLARATION,
    NODE_IF_STATEMENT,
    NODE_WHILE_STATEMENT,
    NODE_DO_WHILE_STATEMENT,
    NODE_FOR_STATEMENT,
    NODE_SWITCH_STATEMENT,
    NODE_MATCH_STATEMENT,
    NODE_RETURN_STATEMENT,
    NODE_BREAK_STATEMENT,
    NODE_CONTINUE_STATEMENT,
    NODE_TRY_STATEMENT,
    NODE_CATCH_CLAUSE,
    NODE_DEFER_STATEMENT,
    
    // Expressions
    NODE_BINARY_EXPRESSION,
    NODE_UNARY_EXPRESSION,
    NODE_LITERAL_EXPRESSION,
    NODE_IDENTIFIER_EXPRESSION,
    NODE_CALL_EXPRESSION,
    NODE_MEMBER_ACCESS_EXPRESSION,
    NODE_INDEX_EXPRESSION,
    NODE_CONDITIONAL_EXPRESSION,
    NODE_ASSIGNMENT_EXPRESSION,
    NODE_LAMBDA_EXPRESSION,
    NODE_ARRAY_EXPRESSION,
    NODE_STRUCT_EXPRESSION,
    NODE_COMMAND_EXECUTION_EXPRESSION,
    
    // Types
    NODE_TYPE_REFERENCE,
    NODE_ARRAY_TYPE,
    NODE_POINTER_TYPE,
    NODE_REFERENCE_TYPE,
    NODE_FUNCTION_TYPE,
    NODE_GENERIC_TYPE,
    NODE_TUPLE_TYPE,
    
    // Patterns
    NODE_PATTERN_LITERAL,
    NODE_PATTERN_IDENTIFIER,
    NODE_PATTERN_STRUCT,
    NODE_PATTERN_TUPLE,
    NODE_PATTERN_ARRAY,
    NODE_PATTERN_REST,
    NODE_PATTERN_GUARD,
    
    NODE_COUNT
} NodeType;

/* Forward declarations for node structures */
typedef struct ASTNode ASTNode;

/* Type node structure */
typedef struct {
    enum {
        TYPE_PRIMITIVE,
        TYPE_ARRAY,
        TYPE_POINTER,
        TYPE_REFERENCE,
        TYPE_FUNCTION,
        TYPE_STRUCT,
        TYPE_ENUM,
        TYPE_GENERIC,
        TYPE_TUPLE
    } kind;
    
    union {
        struct {
            StringView name;
        } primitive;
        
        struct {
            ASTNode* element_type;
            ASTNode* size_expr;  // Optional, NULL for slices
        } array;
        
        struct {
            ASTNode* pointee_type;
            bool is_mutable;
        } pointer;
        
        struct {
            ASTNode* referenced_type;
            bool is_mutable;
        } reference;
        
        struct {
            ASTNode** parameter_types;
            size_t parameter_count;
            ASTNode* return_type;
        } function;
        
        struct {
            StringView name;
            ASTNode** type_arguments;
            size_t type_argument_count;
        } named;
        
        struct {
            ASTNode** fields;
            size_t field_count;
        } tuple;
    } data;
} TypeNode;

typedef struct {
    enum {
        EXPR_BINARY,
        EXPR_UNARY,
        EXPR_LITERAL,
        EXPR_IDENTIFIER,
        EXPR_CALL,
        EXPR_MEMBER_ACCESS,
        EXPR_INDEX,
        EXPR_CONDITIONAL,
        EXPR_ASSIGNMENT,
        EXPR_LAMBDA,
        EXPR_ARRAY,
        EXPR_STRUCT,
        EXPR_COMMAND_EXECUTION
    } kind;

    ASTNode* type;  // Type of the expression after type checking
    bool is_lvalue; // Whether this expression can appear on the left side of an assignment

    union {
        struct {
            TokenType operator;
            ASTNode* left;
            ASTNode* right;
        } binary;

        struct {
            TokenType operator;
            ASTNode* operand;
        } unary;

        struct {
            enum {
                LITERAL_INTEGER,
                LITERAL_FLOAT,
                LITERAL_STRING,
                LITERAL_CHAR,
                LITERAL_BOOL,
                LITERAL_NULL
            } kind;

            union {
                int64_t int_value;
                double float_value;
                StringView string_value;
                char char_value;
                bool bool_value;
            } value;
        } literal;

        struct {
            StringView name;
            int symbol_index;  // Index into symbol table, set during semantic analysis
        } identifier;

        struct {
            ASTNode* callee;
            ASTNode** arguments;
            size_t argument_count;
        } call;

        struct {
            ASTNode* object;
            StringView member;
            bool is_arrow;  // Whether this is obj->member (true) or obj.member (false)
        } member_access;

        struct {
            ASTNode* array;
            ASTNode* index;
        } index;

        struct {
            ASTNode* condition;
            ASTNode* then_branch;
            ASTNode* else_branch;
        } conditional;

        struct {
            TokenType operator;
            ASTNode* left;
            ASTNode* right;
        } assignment;

        struct {
            ASTNode** parameters;
            size_t parameter_count;
            ASTNode* body;
            ASTNode* return_type;
        } lambda;

        struct {
            ASTNode** elements;
            size_t element_count;
        } array;

        struct {
            StringView name;
            StringView* field_names;
            ASTNode** field_values;
            size_t field_count;
        } struct_expr;

        struct {
            StringView command;
        } command_execution;
    } data;
} ExpressionNode;

/* Statement node structure */
typedef struct {
    enum {
        STMT_BLOCK,
        STMT_EXPRESSION,
        STMT_VARIABLE_DECLARATION,
        STMT_IF,
        STMT_WHILE,
        STMT_DO_WHILE,
        STMT_FOR,
        STMT_SWITCH,
        STMT_MATCH,
        STMT_RETURN,
        STMT_BREAK,
        STMT_CONTINUE,
        STMT_TRY,
        STMT_DEFER
    } kind;

    union {
        struct {
            ASTNode** statements;
            size_t statement_count;
            bool creates_scope;
        } block;

        struct {
            ASTNode* expression;
        } expression;

        struct {
            StringView name;
            ASTNode* type;
            ASTNode* initializer;
            bool is_mutable;
            bool is_const;
            int symbol_index;  // Set during semantic analysis
        } variable_declaration;

        struct {
            ASTNode* condition;
            ASTNode* then_branch;
            ASTNode* else_branch;  // Optional
        } if_statement;

        struct {
            ASTNode* condition;
            ASTNode* body;
        } while_statement;

        struct {
            ASTNode* body;
            ASTNode* condition;
        } do_while_statement;

        struct {
            ASTNode* initializer;  // Optional
            ASTNode* condition;    // Optional
            ASTNode* increment;    // Optional
            ASTNode* body;
        } for_statement;

        struct {
            ASTNode* expression;
            ASTNode** cases;
            size_t case_count;
            ASTNode* default_case;  // Optional
        } switch_statement;

        struct {
            ASTNode* expression;
            ASTNode** arms;
            size_t arm_count;
        } match_statement;

        struct {
            ASTNode* value;  // Optional
        } return_statement;

        struct {
            // No data needed for break
        } break_statement;

        struct {
            // No data needed for continue
        } continue_statement;

        struct {
            ASTNode* body;
            ASTNode** catch_clauses;
            size_t catch_count;
            ASTNode* finally_block;  // Optional
        } try_statement;

        struct {
            ASTNode* statement;
        } defer_statement;
    } data;
} StatementNode;

/* Declaration node structure */
typedef struct {
    enum {
        DECL_FUNCTION,
        DECL_STRUCT,
        DECL_ENUM,
        DECL_TYPE_ALIAS,
        DECL_IMPORT,
        DECL_USE,
        DECL_CONST,
        DECL_STATIC,
        DECL_MODULE
    } kind;

    StringView name;
    bool is_public;
    bool is_extern;

    union {
        struct {
            ASTNode** parameters;
            size_t parameter_count;
            ASTNode* return_type;
            ASTNode* body;  // Optional, NULL for forward declarations
            bool is_variadic;
        } function;

        struct {
            ASTNode** fields;
            size_t field_count;
            ASTNode** type_parameters;
            size_t type_parameter_count;
            ASTNode** methods;
            size_t method_count;
        } struct_decl;

        struct {
            ASTNode** variants;
            size_t variant_count;
        } enum_decl;

        struct {
            ASTNode* target_type;
        } type_alias;

        struct {
            StringView module_path;
            StringView* imported_symbols;
            size_t imported_count;
            bool is_wildcard;
        } import_decl;

        struct {
            StringView module_path;
        } use_decl;

        struct {
            ASTNode* type;
            ASTNode* value;
        } const_decl;

        struct {
            ASTNode* type;
            ASTNode* value;
        } static_decl;

        struct {
            StringView* exports;
            size_t export_count;
        } module_decl;
    } data;
} DeclarationNode;

/* AST node structure */
struct ASTNode {
    NodeType type;
    SourceLocation location;

    union {
        struct {
            ASTNode** declarations;
            size_t declaration_count;
        } program;

        ExpressionNode expression;
        StatementNode statement;
        DeclarationNode declaration;
        TypeNode type_node;
    } data;
};

/* Symbol types */
typedef enum {
    SYMBOL_VARIABLE,
    SYMBOL_FUNCTION,
    SYMBOL_TYPE,
    SYMBOL_PARAMETER,
    SYMBOL_MODULE
} SymbolKind;

/* Symbol structure for the symbol table */
typedef struct {
    StringView name;
    SymbolKind kind;
    ASTNode* declaration;
    ASTNode* type;
    bool is_mutable;
    bool is_const;
    bool is_public;
    int scope_level;
    int index;  // Unique identifier for the symbol
} Symbol;

/* Symbol table structure */
typedef struct SymbolTable {
    struct SymbolTable* parent;
    HashMap* symbols;
    int scope_level;
} SymbolTable;

/* Scope for code generation */
typedef struct {
    HashMap* variables;  // Maps variable names to storage locations
    size_t stack_size;   // Size of all variables in this scope
    size_t alignment;    // Required stack alignment
} Scope;

/* Error reporting structure */
typedef struct {
    enum {
        ERROR_LEXICAL,
        ERROR_SYNTAX,
        ERROR_SEMANTIC,
        ERROR_TYPE,
        ERROR_INTERNAL
    } kind;

    SourceLocation location;
    char* message;
    bool is_warning;
} Error;

/* Diagnostic context */
typedef struct {
    Error** errors;
    size_t error_count;
    size_t error_capacity;

    bool has_errors;
    bool has_warnings;
    bool verbose;
    int warning_level;  // 0 = none, 1 = standard, 2 = extra, 3 = all
} DiagnosticContext;

/* Compiler options */
typedef struct {
    char* input_file;
    char* output_file;
    bool optimize;
    int optimization_level;  // 0-3, higher is more aggressive
    bool debug_info;
    bool warnings_as_errors;
    bool verbose;
    bool check_only;  // Only perform semantic analysis, don't generate code
    char** import_paths;
    size_t import_path_count;
    char* target_triple;  // e.g., "x86_64-unknown-linux-gnu"
} CompilerOptions;

/* Compiler context */
typedef struct {
    char* source;
    size_t source_length;
    char* filename;

    Token* tokens;
    size_t token_count;
    size_t token_capacity;
    size_t current_token;

    ASTNode* ast;

    Arena* ast_arena;
    Arena* string_arena;
    Arena* temp_arena;

    SymbolTable* global_symbols;
    SymbolTable* current_symbols;

    DiagnosticContext diagnostics;
    CompilerOptions options;

    HashMap* string_interner;
} CompilerContext;

/*******************************************************************************
 * Memory Management
 ******************************************************************************/

/* Initialize a new memory arena */
Arena* create_arena(size_t initial_capacity) {
    Arena* arena = (Arena*)malloc(sizeof(Arena));
    if (!arena) {
        return NULL;
    }

    arena->buffer = (char*)malloc(initial_capacity);
    if (!arena->buffer) {
        free(arena);
        return NULL;
    }

    arena->capacity = initial_capacity;
    arena->used = 0;
    arena->next = NULL;

    return arena;
}

/* Allocate memory from an arena */
void* arena_alloc(Arena* arena, size_t size) {
    // Align size to 8 bytes
    size = (size + 7) & ~7;

    if (arena->used + size > arena->capacity) {
        // Allocate a new arena segment
        size_t new_capacity = arena->capacity * 2;
        if (new_capacity < size) {
            new_capacity = size * 2;
        }

        Arena* new_arena = create_arena(new_capacity);
        if (!new_arena) {
            return NULL;
        }

        new_arena->next = arena->next;
        arena->next = new_arena;

        return arena_alloc(new_arena, size);
    }

    void* ptr = arena->buffer + arena->used;
    arena->used += size;
    return ptr;
}

/* Reset an arena without freeing it */
void arena_reset(Arena* arena) {
    Arena* current = arena;
    while (current) {
        current->used = 0;
        current = current->next;
    }
}

/* Free an entire arena and all its segments */
void arena_free(Arena* arena) {
    Arena* current = arena;
    while (current) {
        Arena* next = current->next;
        free(current->buffer);
        free(current);
        current = next;
    }
}

/* Initialize a hash map */
HashMap* hashmap_create(size_t initial_capacity, float load_factor) {
    HashMap* map = (HashMap*)malloc(sizeof(HashMap));
    if (!map) {
        return NULL;
    }

    map->capacity = initial_capacity;
    map->size = 0;
    map->load_factor = load_factor;

    map->keys = (void**)calloc(initial_capacity, sizeof(void*));
    map->values = (void**)calloc(initial_capacity, sizeof(void*));
    map->occupied = (bool*)calloc(initial_capacity, sizeof(bool));

    if (!map->keys || !map->values || !map->occupied) {
        free(map->keys);
        free(map->values);
        free(map->occupied);
        free(map);
        return NULL;
    }

    return map;
}

/* Hash function for strings */
size_t string_hash(const char* str, size_t len) {
    size_t hash = 5381;
    for (size_t i = 0; i < len; i++) {
        hash = ((hash << 5) + hash) + (unsigned char)str[i];
    }
    return hash;
}

/* Hash function for StringView */
size_t stringview_hash(StringView* sv) {
    return string_hash(sv->data, sv->length);
}

/* Compare two StringViews for equality */
bool stringview_equals(StringView* a, StringView* b) {
    if (a->length != b->length) {
        return false;
    }
    return memcmp(a->data, b->data, a->length) == 0;
}

/* Get an item from the hash map */
void* hashmap_get(HashMap* map, void* key, size_t (*hash_func)(void*), bool (*equals_func)(void*, void*)) {
    size_t hash = hash_func(key);
    size_t index = hash % map->capacity;
    size_t start_index = index;

    do {
        if (!map->occupied[index]) {
            return NULL;
        }

        if (equals_func(map->keys[index], key)) {
            return map->values[index];
        }

        index = (index + 1) % map->capacity;
    } while (index != start_index);

    return NULL;
}

/* Resize the hash map */
bool hashmap_resize(HashMap* map, size_t new_capacity, size_t (*hash_func)(void*), bool (*equals_func)(void*, void*)) {
    void** old_keys = map->keys;
    void** old_values = map->values;
    bool* old_occupied = map->occupied;
    size_t old_capacity = map->capacity;

    map->keys = (void**)calloc(new_capacity, sizeof(void*));
    map->values = (void**)calloc(new_capacity, sizeof(void*));
    map->occupied = (bool*)calloc(new_capacity, sizeof(bool));

    if (!map->keys || !map->values || !map->occupied) {
        map->keys = old_keys;
        map->values = old_values;
        map->occupied = old_occupied;
        map->capacity = old_capacity;
        return false;
    }

    map->capacity = new_capacity;
    map->size = 0;

    for (size_t i = 0; i < old_capacity; i++) {
        if (old_occupied[i]) {
            hashmap_put(map, old_keys[i], old_values[i], hash_func, equals_func);
        }
    }

    free(old_keys);
    free(old_values);
    free(old_occupied);

    return true;
}

/* Put an item in the hash map */
bool hashmap_put(HashMap* map, void* key, void* value, size_t (*hash_func)(void*), bool (*equals_func)(void*, void*)) {
    if (map->size >= map->capacity * map->load_factor) {
        if (!hashmap_resize(map, map->capacity * 2, hash_func, equals_func)) {
            return false;
        }
    }

    size_t hash = hash_func(key);
    size_t index = hash % map->capacity;
    size_t start_index = index;

    do {
        if (!map->occupied[index] || equals_func(map->keys[index], key)) {
            map->keys[index] = key;
            map->values[index] = value;
            
            if (!map->occupied[index]) {
                map->occupied[index] = true;
                map->size++;
            }
            
            return true;
        }

        index = (index + 1) % map->capacity;
    } while (index != start_index);

    return false;
}

/* Remove an item from the hash map */
bool hashmap_remove(HashMap* map, void* key, size_t (*hash_func)(void*), bool (*equals_func)(void*, void*)) {
    size_t hash = hash_func(key);
    size_t index = hash % map->capacity;
    size_t start_index = index;

    do {
        if (!map->occupied[index]) {
            return false;
        }

        if (equals_func(map->keys[index], key)) {
            map->occupied[index] = false;
            map->size--;
            
            // Re-hash subsequent entries to maintain proper chains
            index = (index + 1) % map->capacity;
            while (map->occupied[index]) {
                void* rehash_key = map->keys[index];
                void* rehash_value = map->values[index];
                
                map->occupied[index] = false;
                map->size--;
                
                hashmap_put(map, rehash_key, rehash_value, hash_func, equals_func);
                
                index = (index + 1) % map->capacity;
            }
            
            return true;
        }

        index = (index + 1) % map->capacity;
    } while (index != start_index);

    return false;
}

/* Free a hash map */
void hashmap_free(HashMap* map) {
    free(map->keys);
    free(map->values);
    free(map->occupied);
    free(map);
}

/* Initialize a dynamic array */
Array* array_create(size_t element_size, size_t initial_capacity) {
    Array* array = (Array*)malloc(sizeof(Array));
    if (!array) {
        return NULL;
    }

    array->data = malloc(element_size * initial_capacity);
    if (!array->data) {
        free(array);
        return NULL;
    }

    array->element_size = element_size;
    array->capacity = initial_capacity;
    array->length = 0;

    return array;
}

/* Resize a dynamic array */
bool array_resize(Array* array, size_t new_capacity) {
    void* new_data = realloc(array->data, array->element_size * new_capacity);
    if (!new_data) {
        return false;
    }

    array->data = new_data;
    array->capacity = new_capacity;
    return true;
}

/* Push an item onto the array */
bool array_push(Array* array, void* element) {
    if (array->length >= array->capacity) {
        if (!array_resize(array, array->capacity * 2)) {
            return false;
        }
    }

    char* dest = (char*)array->data + (array->length * array->element_size);
    memcpy(dest, element, array->element_size);
    array->length++;

    return true;
}

/* Get an item from the array */
void* array_get(Array* array, size_t index) {
    if (index >= array->length) {
        return NULL;
    }

    return (char*)array->data + (index * array->element_size);
}

/* Set an item in the array */
bool array_set(Array* array, size_t index, void* element) {
    if (index >= array->length) {
        return false;
    }

    char* dest = (char*)array->data + (index * array->element_size);
    memcpy(dest, element, array->element_size);

    return true;
}

/* Pop an item from the array */
bool array_pop(Array* array, void* out_element) {
    if (array->length == 0) {
        return false;
    }

    array->length--;
    
    if (out_element) {
        char* src = (char*)array->data + (array->length * array->element_size);
        memcpy(out_element, src, array->element_size);
    }

    return true;
}

/* Free an array */
void array_free(Array* array) {
    free(array->data);
    free(array);
}

/* Create a string view */
StringView string_view_create(const char* str, size_t length, bool take_ownership) {
    StringView sv;
    if (take_ownership) {
        sv.data = (char*)str;
    } else {
        sv.data = (char*)malloc(length + 1);
        if (sv.data) {
            memcpy(sv.data, str, length);
            sv.data[length] = '\0';
        }
    }
    sv.length = length;
    sv.owned = take_ownership || sv.data != str;
    return sv;
}

/* Create a string view from a C string */
StringView string_view_from_cstring(const char* str) {
    return string_view_create(str, strlen(str), false);
}

/* Free a string view */
void string_view_free(StringView* sv) {
    if (sv->owned && sv->data) {
        free(sv->data);
        sv->data = NULL;
        sv->length = 0;
    }
}

/* String view to C string (null-terminated) */
char* string_view_to_cstring(StringView* sv, Arena* arena) {
    char* result;
    if (arena) {
        result = (char*)arena_alloc(arena, sv->length + 1);
    } else {
        result = (char*)malloc(sv->length + 1);
    }

    if (!result) {
        return NULL;
    }

    memcpy(result, sv->data, sv->length);
    result[sv->length] = '\0';
    return result;
}

/* Compare string views */
int string_view_compare(StringView* a, StringView* b) {
    size_t min_len = a->length < b->length ? a->length : b->length;
    int result = memcmp(a->data, b->data, min_len);
    
    if (result != 0) {
        return result;
    }
    
    if (a->length < b->length) {
        return -1;
    } else if (a->length > b->length) {
        return 1;
    } else {
        return 0;
    }
}

/*******************************************************************************
 * Lexer
 ******************************************************************************/

/* Lexer context */
typedef struct {
    const char* source;
    size_t source_length;
    size_t position;
    size_t line;
    size_t column;
    const char* filename;
    
    Arena* string_arena;
    DiagnosticContext* diagnostics;
    HashMap* keywords;
} LexerContext;

/* Initialize a lexer */
LexerContext* lexer_create(const char* source, size_t source_length, const char* filename, Arena* string_arena, DiagnosticContext* diagnostics) {
    LexerContext* lexer = (LexerContext*)malloc(sizeof(LexerContext));
    if (!lexer) {
        return NULL;
    }

    lexer->source = source;
    lexer->source_length = source_length;
    lexer->position = 0;
    lexer->line = 1;
    lexer->column = 1;
    lexer->filename = filename;
    lexer->string_arena = string_arena;
    lexer->diagnostics = diagnostics;
    
    // Initialize keyword map
    lexer->keywords = hashmap_create(64, 0.75f);
    
    // Add keywords
    struct {
        const char* keyword;
        TokenType type;
    } keywords[] = {
        {"auto", TOKEN_AUTO},
        {"break", TOKEN_BREAK},
        {"case", TOKEN_CASE},
        {"const", TOKEN_CONST},
        {"continue", TOKEN_CONTINUE},
        {"default", TOKEN_DEFAULT},
        {"do", TOKEN_DO},
        {"else", TOKEN_ELSE},
        {"enum", TOKEN_ENUM},
        {"extern", TOKEN_EXTERN},
        {"fn", TOKEN_FN},
        {"for", TOKEN_FOR},
        {"if", TOKEN_IF},
        {"import", TOKEN_IMPORT},
        {"let", TOKEN_LET},
        {"match", TOKEN_MATCH},
        {"mut", TOKEN_MUT},
        {"return", TOKEN_RETURN},
        {"struct", TOKEN_STRUCT},
        {"switch", TOKEN_SWITCH},
        {"type", TOKEN_TYPE},
        {"use", TOKEN_USE},
        {"var", TOKEN_VAR},
        {"void", TOKEN_VOID},
        {"while", TOKEN_WHILE},
        {"true", TOKEN_BOOL},
        {"false", TOKEN_BOOL}
    };
    
    for (size_t i = 0; i < sizeof(keywords) / sizeof(keywords[0]); i++) {
        StringView* key = (StringView*)arena_alloc(string_arena, sizeof(StringView));
        *key = string_view_from_cstring(keywords[i].keyword);
        
        TokenType* type = (TokenType*)arena_alloc(string_arena, sizeof(TokenType));
        *type = keywords[i].type;
        
        hashmap_put(lexer->keywords, key, type, (size_t(*)(void*))stringview_hash, (bool(*)(void*,void*))stringview_equals);
    }
    
    return lexer;
}

/* Free a lexer */
void lexer_free(LexerContext* lexer) {
    hashmap_free(lexer->keywords);
    free(lexer);
}

/* Report a lexer error */
void lexer_error(LexerContext* lexer, const char* message) {
    Error* error = (Error*)malloc(sizeof(Error));
    if (!error) {
        return;
    }

    error->kind = ERROR_LEXICAL;
    error->location.filename = lexer->filename;
    error->location.line = lexer->line;
    error->location.column = lexer->column;
    error->location.offset = lexer->position;
    error->message = strdup(message);
    error->is_warning = false;

    if (lexer->diagnostics->error_count >= lexer->diagnostics->error_capacity) {
        size_t new_capacity = lexer->diagnostics->error_capacity == 0 ? 16 : lexer->diagnostics->error_capacity * 2;
        Error** new_errors = (Error**)realloc(lexer->diagnostics->errors, new_capacity * sizeof(Error*));
        
        if (!new_errors) {
            free(error->message);
            free(error);
            return;
        }
        
        lexer->diagnostics->errors = new_errors;
        lexer->diagnostics->error_capacity = new_capacity;
    }

    lexer->diagnostics->errors[lexer->diagnostics->error_count++] = error;
    lexer->diagnostics->has_errors = true;
}

/* Get the current character */
char lexer_current(LexerContext* lexer) {
    if (lexer->position >= lexer->source_length) {
        return '\0';
    }
    return lexer->source[lexer->position];
}

/* Peek ahead n characters */
char lexer_peek(LexerContext* lexer, size_t offset) {
    if (lexer->position + offset >= lexer->source_length) {
        return '\0';
    }
    return lexer->source[lexer->position + offset];
}

/* Advance the lexer */
void lexer_advance(LexerContext* lexer) {
    if (lexer_current(lexer) == '\n') {
        lexer->line++;
        lexer->column = 1;
    } else {
        lexer->column++;
    }
    
    lexer->position++;
}

/* Skip whitespace */
void lexer_skip_whitespace(LexerContext* lexer) {
    while (lexer->position < lexer->source_length) {
        char c = lexer_current(lexer);
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            lexer_advance(lexer);
        } else {
            break;
        }
    }
}

/* Skip comments */
void lexer_skip_comments(LexerContext* lexer) {
    if (lexer_current(lexer) == '/' && lexer_peek(lexer, 1) == '/') {
        // Line comment
        lexer_advance(lexer);
        lexer_advance(lexer);
        
        while (lexer->position < lexer->source_length) {
            if (lexer_current(lexer) == '\n') {
                lexer_advance(lexer);
                break;
            }
            lexer_advance(lexer);
        }
    } else if (lexer_current(lexer) == '/' && lexer_peek(lexer, 1) == '*') {
        // Block comment
        lexer_advance(lexer);
        lexer_advance(lexer);
        
        while (lexer->position < lexer->source_length) {
            if (lexer_current(lexer) == '*' && lexer_peek(lexer, 1) == '/') {
                lexer_advance(lexer);
                lexer_advance(lexer);
                break;
            }
            lexer_advance(lexer);
        }
    }
}

/* Read an identifier */
Token lexer_read_identifier(LexerContext* lexer) {
    size_t start = lexer->position;
    size_t line = lexer->line;
    size_t column = lexer->column;
    
    while (lexer->position < lexer->source_length) {
        char c = lexer_current(lexer);
        if (isalnum(c) || c == '_') {
            lexer_advance(lexer);
        } else {
            break;
        }
    }
    
    StringView lexeme = string_view_create(lexer->source + start, lexer->position - start, false);
    
    // Check if it's a keyword
    TokenType* keyword_type = (TokenType*)hashmap_get(lexer->keywords, &lexeme, (size_t(*)(void*))stringview_hash, (bool(*)(void*,void*))stringview_equals);
    
    Token token;
    token.location.filename = lexer->filename;
    token.location.line = line;
    token.location.column = column;
    token.location.offset = start;
    token.lexeme = lexeme;
    
    if (keyword_type) {
        token.type = *keyword_type;
        
        if (token.type == TOKEN_BOOL) {
            token.value.bool_value = (lexeme.length == 4 && strncmp(lexeme.data, "true", 4) == 0);
        }
    } else {
        token.type = TOKEN_IDENTIFIER;
    }
    
    return token;
}

/* Read a number */
Token lexer_read_number(LexerContext* lexer) {
    size_t


/* Working on it...*/
